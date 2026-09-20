# Run with unittest discovery from the repository root; no live credentials are needed.
"""Regression coverage for the codebase safety assessment; synthetic APIs only."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import netskope_mist_connector as c
import test_lifecycle as fixtures
from test_lifecycle import config


class CleanupSafetyTests(unittest.TestCase):
    setUp = fixtures.LifecycleTests.setUp
    tearDown = fixtures.LifecycleTests.tearDown
    success = fixtures.LifecycleTests.success

    def test_reassigned_template_blocks_all_cleanup_writes(self):
        self.success()
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.api.site_rows = [{'id': 'replacement', 'org_id': 'org', 'gatewaytemplate_id': 'tpl'}]
        self.api.settings['replacement'] = {'vars': {}}
        before = list(self.api.calls)
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, before)
        self.assertEqual(len(self.api.tunnels), 1)

    def test_renamed_owned_tunnel_blocks_cleanup(self):
        self.success()
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.api.tunnels[0]['site'] = 'manually-repurposed'
        before = list(self.api.calls)
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, before)

    def test_invalid_grace_cannot_bypass_retirement_wait(self):
        self.success()
        self.api.site_rows = []
        self.config['deletion_grace_seconds'] = float('nan')
        before = list(self.api.calls)
        with self.assertRaises(c.ReconcileError):
            self.worker.reconcile()
        self.assertEqual(self.api.calls, before)

    def test_masked_pending_version_can_be_preserved_for_another_connection(self):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['secret_readback'] = 'masked'
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        self.success()
        self.api.pops[0]['gateway'] = '192.0.2.88'
        self.api.fail_put = True
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        key, record = next(iter(self.state.records().items()))
        document, _ = self.api.template('tpl')
        name = 'mist-' + key[:24]
        document['tunnels'][name]['psk'] = '********'
        payload = self.worker.write_sections(document, 'tpl', {'tunnels'})
        self.assertEqual(payload['tunnels'][name]['peer'], '192.0.2.88')
        self.assertEqual(payload['tunnels'][name]['psk'], self.state.secret(key))
        document['tunnels'][name]['peer'] = '192.0.2.99'
        with self.assertRaises(c.ReconcileError):
            self.worker.write_sections(document, 'tpl', {'tunnels'})

    def test_malformed_pop_advertisements_report_errors_without_writes(self):
        for field, value in [('options', None), ('options', {'phase2': None}), ('bandwidth', None)]:
            with self.subTest(field=field):
                original = self.api.pops[0][field]
                self.api.pops[0][field] = value
                self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
                self.assertEqual(self.api.calls, [])
                self.api.pops[0][field] = original

    def test_masked_peer_drift_still_blocks_overwrite(self):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['secret_readback'] = 'masked'
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        self.success()
        key = self.worker.key('site1', 'wan1')
        self.api.templates['tpl']['tunnels']['mist-' + key[:24]]['peer'] = 'external'
        before = list(self.api.calls)
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, before)

    def test_inbox_accepts_duplicate_when_full(self):
        with self.state.db:
            self.state.db.executemany('INSERT INTO inbox (digest, created) VALUES (?, ?)',
                                     [(str(i), 1) for i in range(10000)])
        self.state.enqueue('0')
        self.assertEqual(len(self.state.pending()), 10000)
        with self.assertRaises(c.ReconcileError):
            self.state.enqueue('new')


class StrictTransportTests(unittest.TestCase):
    def setUp(self):
        self.api = c.LifecycleAPI(SimpleNamespace(
            mist_base_url='https://mist.invalid', netskope_tenant_url='https://netskope.invalid',
            mist_api_token='fake', netskope_api_token='fake', mist_org_id='org'))

    def response(self, status=200, body=None, content=b'null', headers=None):
        return SimpleNamespace(status_code=status, content=content, headers=headers or {}, json=lambda: body)

    def test_only_404_establishes_site_absence(self):
        for status, body, content in [(200, None, b'null'), (200, None, b''), (204, None, b''),
                                      (200, [], b'[]'), (403, None, b'')]:
            with self.subTest(status=status, content=content):
                self.api.mist.request = Mock(return_value=self.response(status, body, content))
                with self.assertRaises(c.ReconcileError):
                    self.api.site('site1')
        self.api.mist.request = Mock(return_value=self.response(404))
        self.assertIsNone(self.api.site('site1'))

    def test_empty_template_read_cannot_skip_cleanup_verification(self):
        self.api.mist.request = Mock(return_value=self.response())
        with self.assertRaises(c.ReconcileError):
            self.api.template('tpl')

    def test_read_timeout_retries_with_bounded_backoff(self):
        self.api.mist.request = Mock(side_effect=[c.requests.Timeout(), c.requests.ConnectionError(),
                                                self.response(body={'id': 'site1', 'org_id': 'org'})])
        with patch.object(c.time, 'sleep') as sleep:
            self.assertEqual(self.api.site('site1')['id'], 'site1')
        self.assertEqual(self.api.mist.request.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_mutation_timeout_is_never_retried(self):
        self.api.netskope.request = Mock(side_effect=c.requests.Timeout('sensitive payload'))
        with patch.object(c.time, 'sleep') as sleep:
            with self.assertRaises(c.ReconcileError) as caught:
                self.api.create({'psk': 'sensitive payload'})
        self.assertNotIn('sensitive', str(caught.exception))
        self.assertEqual(self.api.netskope.request.call_count, 1)
        sleep.assert_not_called()

    def test_retry_after_is_capped_and_auth_errors_not_retried(self):
        self.api.mist.request = Mock(side_effect=[self.response(429, headers={'Retry-After': '999'}),
                                                self.response(403)])
        with patch.object(c.time, 'sleep') as sleep:
            with self.assertRaises(c.ReconcileError):
                self.api.site('site1')
        sleep.assert_called_once_with(30)
        self.assertEqual(self.api.mist.request.call_count, 2)

    def test_read_retry_budget_is_finite(self):
        self.api.mist.request = Mock(side_effect=c.requests.Timeout())
        with patch.object(c.time, 'sleep') as sleep:
            with self.assertRaises(c.ReconcileError):
                self.api.site('site1')
        self.assertEqual(self.api.mist.request.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_conditional_update_preserves_etag_and_disables_redirects(self):
        self.api.mist.request = Mock(return_value=self.response(204, content=b''))
        self.api.put_template('tpl', {'tunnels': {}}, 'revision-2')
        kwargs = self.api.mist.request.call_args.kwargs
        self.assertEqual(kwargs['headers'], {'If-Match': 'revision-2'})
        self.assertFalse(kwargs['allow_redirects'])

    def test_non_scalar_mist_id_is_rejected_safely(self):
        self.api.request = Mock(return_value=([{'id': ['bad'], 'org_id': 'org'}], {}))
        with self.assertRaises(c.ReconcileError):
            self.api.sites()

    def test_invalid_resource_ids_fail_closed(self):
        for value in [True, None, [], {}, '', '../other']:
            with self.subTest(value=value):
                with self.assertRaises(c.ReconcileError):
                    c.checked_id(value)

    def test_invalid_inventory_ids_fail_closed(self):
        for value in [None, True, [], {}, '../other']:
            with self.subTest(value=value):
                self.api.request = Mock(return_value=({'result': [{'id': value}], 'total': 1}, {}))
                with self.assertRaises(c.ReconcileError):
                    self.api.inventory('tunnels')


class ConfigSafetyTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'config.json'
            path.write_text(json.dumps(data))
            return c.load_lifecycle_config(path)

    def test_nonfinite_and_boolean_timers_rejected(self):
        for field in ['reconcile_interval_seconds', 'deletion_grace_seconds']:
            for value in [float('nan'), float('inf'), -float('inf'), True, '600', 0]:
                with self.subTest(field=field, value=value):
                    data = config()
                    data[field] = value
                    with self.assertRaises(c.ReconcileError):
                        self.load(data)

    def test_malformed_connection_ids_have_safe_errors(self):
        for value in [[], {}, True, None]:
            with self.subTest(value=value):
                data = config()
                data['profiles']['srx']['connections'][0]['id'] = value
                with self.assertRaises(c.ReconcileError):
                    self.load(data)

    def test_invalid_entry_and_health_shapes_rejected_before_execution(self):
        for field, value in [('mist_entries', [None]), ('mist_entries', [{'path': ['x']}]),
                             ('health_checks', [None]), ('health_checks', [{'path': 'status', 'equals': 'up'}]),
                             ('secret_readback', 'typo')]:
            with self.subTest(field=field, value=value):
                data = config()
                data['profiles']['srx']['connections'][0][field] = value
                with self.assertRaises(c.ReconcileError):
                    self.load(data)

    def test_valid_example_remains_loadable(self):
        self.assertEqual(c.load_lifecycle_config('examples/lifecycle.example.json')['version'], 1)
