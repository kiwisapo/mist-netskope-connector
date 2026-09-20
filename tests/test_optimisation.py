# Transport, state and receiver checks run locally, including loopback HTTP tests.
"""Regression coverage for the optimisation pass; synthetic APIs and loopback only.

Covers the retired legacy surface, completeness checks derived from the vendor
API review, state start-up/durability hardening, the bounded receiver and
graceful shutdown. Nothing here demonstrates live vendor interoperability."""
import hashlib
import hmac
import io
import json
import os
import signal
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import netskope_mist_connector as c
import test_lifecycle as fixtures

KEY = 'a' * 64
ENV = {'NETSKOPE_TENANT_URL': 'https://netskope.invalid', 'NETSKOPE_API_TOKEN': 'ns-token-value',
       'MIST_BASE_URL': 'https://mist.invalid', 'MIST_API_TOKEN': 'mist-token-value', 'MIST_ORG_ID': 'org'}


def fake_cfg():
    return SimpleNamespace(mist_base_url='https://mist.invalid', netskope_tenant_url='https://netskope.invalid',
                           mist_api_token='fake', netskope_api_token='fake', mist_org_id='org')


def response(status=200, body=None, headers=None):
    content = b'' if body is None else json.dumps(body).encode()
    return SimpleNamespace(status_code=status, content=content, headers=headers or {}, json=lambda: body)


class RetiredLegacySurfaceTests(unittest.TestCase):
    def test_guessed_schema_and_blind_retry_helpers_are_gone(self):
        for name in ('process_site', 'build_tunnel_config', 'merge_into_template', 'MistClient', 'NetskopeClient',
                     '_call_with_retry', 'run_batch', 'run_single_site', 'read_sites_csv', 'parse_pop_crypto'):
            self.assertFalse(hasattr(c, name), name)

    def test_legacy_flags_are_rejected_by_the_cli(self):
        for argv in (['--sites-csv', 'sites.csv', '--dry-run'], ['--tunnel-name', 'x']):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                c.parse_args(argv)
            self.assertEqual(raised.exception.code, 2)

    def test_no_mode_and_orphan_lifecycle_flags_fail_safely(self):
        for argv in ([], ['--apply'], ['--dry-run'], ['--serve'], ['--status']):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()) as err:
                self.assertEqual(c.main(argv), 1)
            self.assertTrue(err.getvalue().strip())

    def test_list_pops_uses_strict_transport_and_never_writes(self):
        api = Mock()
        api.inventory.return_value = [{'id': 7, 'name': 'SYD1', 'region': 'APAC', 'acceptingtunnels': True, 'location': 'Sydney'}]
        with patch.dict(os.environ, ENV, clear=False), patch.object(c, 'LifecycleAPI', return_value=api), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(c.main(['--list-pops']), 0)
        api.inventory.assert_called_once_with('pops')
        api.close.assert_called_once_with()
        self.assertEqual([call[0] for call in api.method_calls], ['inventory', 'close'])
        self.assertIn('SYD1', out.getvalue())

    def test_list_pops_cannot_be_combined_with_lifecycle_mode(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(c.main(['--list-pops', '--lifecycle-config', 'examples/lifecycle.example.json']), 1)


class ConfigTests(unittest.TestCase):
    def test_repr_never_contains_tokens(self):
        with patch.dict(os.environ, ENV, clear=False):
            cfg = c.Config.from_env()
        self.assertNotIn('ns-token-value', repr(cfg))
        self.assertNotIn('mist-token-value', repr(cfg))
        self.assertIn('https://mist.invalid', repr(cfg))

    def test_missing_environment_is_a_controlled_error(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(c.ReconcileError) as raised:
            c.Config.from_env()
        self.assertIn('MIST_ORG_ID', str(raised.exception))

    def test_request_budget_must_be_a_positive_integer(self):
        for value in (0, -1, 1.5, True, '5000', None):
            with self.subTest(value=value):
                config = fixtures.config()
                config['mist_hourly_request_budget'] = value
                with self.assertRaises(c.ReconcileError):
                    c.validate_lifecycle_config(config)
        config = fixtures.config()
        config['mist_hourly_request_budget'] = 2500
        c.validate_lifecycle_config(config)

    def test_advertisement_parsers_fail_closed(self):
        self.assertEqual(c.parse_bandwidth_tiers('50 Mbps,100mbps, 1 Gbps,'), [50, 100, 1000])
        for raw in ('50 kbps', 'fast', '50 mbps extra', '-50 mbps'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                c.parse_bandwidth_tiers(raw)
        for raw in ('-5', '8x', '', '1.5h'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                c.parse_duration_to_seconds(raw)
        self.assertEqual(c.parse_duration_to_seconds('3600'), 3600)

    def test_gigabit_tier_is_not_mistaken_for_one_megabit(self):
        api = fixtures.FakeAPI()
        for pop in api.pops:
            pop['bandwidth'] = '1 gbps'
        with tempfile.TemporaryDirectory() as root:
            state = c.LifecycleState(root, {'org': 'org'})
            try:
                config = fixtures.config()
                config['profiles']['srx']['connections'][0]['netskope']['bandwidth'] = 1
                config['validation']['profiles_sha256'] = c.fingerprint(config['profiles'])
                result = c.Reconciler(api, state, config, apply=True).reconcile()
            finally:
                state.close()
        self.assertEqual(result[0]['status'], 'error')
        self.assertEqual(api.calls, [])


class MistInventoryCompletenessTests(unittest.TestCase):
    def setUp(self):
        self.api = c.LifecycleAPI(fake_cfg())

    def sites(self, count, start=0):
        return [{'id': 'site%d' % i, 'org_id': 'org'} for i in range(start, start + count)]

    def test_matching_page_total_is_accepted(self):
        self.api.mist.request = Mock(return_value=response(body=self.sites(2), headers={'X-Page-Total': '2'}))
        self.assertEqual(len(self.api.sites()), 2)

    def test_header_lookup_is_case_insensitive(self):
        self.api.mist.request = Mock(return_value=response(body=self.sites(1), headers={'x-page-total': '3'}))
        with self.assertRaises(c.ReconcileError):
            self.api.sites()

    def test_short_listing_against_total_cannot_establish_absence(self):
        self.api.mist.request = Mock(return_value=response(body=self.sites(2), headers={'X-Page-Total': '5'}))
        with self.assertRaises(c.ReconcileError):
            self.api.sites()

    def test_total_changing_between_pages_fails_closed(self):
        self.api.mist.request = Mock(side_effect=[
            response(body=self.sites(1000), headers={'X-Page-Total': '1001'}),
            response(body=self.sites(1, start=1000), headers={'X-Page-Total': '1002'})])
        with self.assertRaises(c.ReconcileError):
            self.api.sites()

    def test_multi_page_listing_reconciles_with_total(self):
        self.api.mist.request = Mock(side_effect=[
            response(body=self.sites(1000), headers={'X-Page-Total': '1001'}),
            response(body=self.sites(1, start=1000), headers={'X-Page-Total': '1001'})])
        self.assertEqual(len(self.api.sites()), 1001)
        self.assertEqual([call.kwargs['params']['page'] for call in self.api.mist.request.call_args_list], [1, 2])

    def test_smaller_served_page_size_is_not_mistaken_for_the_last_page(self):
        headers = {'X-Page-Total': '3', 'X-Page-Limit': '2'}
        self.api.mist.request = Mock(side_effect=[response(body=self.sites(2), headers=headers),
                                                  response(body=self.sites(1, start=2), headers=headers)])
        self.assertEqual(len(self.api.sites()), 3)

    def test_non_ascii_digit_headers_are_controlled(self):
        self.api.mist.request = Mock(return_value=response(body=self.sites(1), headers={'X-Page-Total': '\u00b2'}))
        with self.assertRaises(c.ReconcileError):
            self.api.sites()
        self.api.mist.request = Mock(side_effect=[response(status=429, headers={'Retry-After': '\u00b2'}),
                                                  response(body=self.sites(1))])
        with patch.object(c.time, 'sleep') as sleep:
            self.assertEqual(len(self.api.sites()), 1)
        sleep.assert_called_once_with(1)

    def test_non_numeric_total_fails_closed_and_absent_header_is_tolerated(self):
        self.api.mist.request = Mock(return_value=response(body=self.sites(1), headers={'X-Page-Total': 'many'}))
        with self.assertRaises(c.ReconcileError):
            self.api.sites()
        self.api.mist.request = Mock(return_value=response(body=self.sites(1)))
        self.assertEqual(len(self.api.sites()), 1)


class NetskopeInventoryContinuationTests(unittest.TestCase):
    def setUp(self):
        self.api = c.LifecycleAPI(fake_cfg())

    def page(self, ids, total):
        return response(body={'result': [{'id': i} for i in ids], 'total': total})

    def test_single_complete_page_sends_no_paging_parameters(self):
        self.api.netskope.request = Mock(return_value=self.page([1, 2], 2))
        self.assertEqual(len(self.api.inventory('tunnels')), 2)
        self.assertIsNone(self.api.netskope.request.call_args.kwargs['params'])

    def test_offset_continuation_assembles_complete_inventory(self):
        self.api.netskope.request = Mock(side_effect=[self.page([1, 2], 5), self.page([3, 4], 5), self.page([5], 5)])
        self.assertEqual([row['id'] for row in self.api.inventory('tunnels')], [1, 2, 3, 4, 5])
        params = [call.kwargs['params'] for call in self.api.netskope.request.call_args_list]
        self.assertEqual(params, [None, {'offset': 2, 'limit': 2}, {'offset': 4, 'limit': 2}])

    def test_api_ignoring_offset_is_detected_by_repeated_ids(self):
        self.api.netskope.request = Mock(side_effect=[self.page([1, 2], 4), self.page([1, 2], 4)])
        with self.assertRaises(c.ReconcileError):
            self.api.inventory('tunnels')

    def test_shifting_total_empty_page_and_overrun_fail_closed(self):
        for pages in ([self.page([1], 3), self.page([2], 4)],
                      [self.page([1], 3), self.page([], 3)],
                      [self.page([1, 2], 3), self.page([3, 4], 3)]):
            with self.subTest(pages=len(pages)):
                self.api.netskope.request = Mock(side_effect=pages)
                with self.assertRaises(c.ReconcileError):
                    self.api.inventory('tunnels')

    def test_invalid_totals_fail_closed(self):
        for total in (True, -1, '2', None, 2.0):
            with self.subTest(total=total):
                self.api.netskope.request = Mock(return_value=response(body={'result': [{'id': 1}, {'id': 2}], 'total': total}))
                with self.assertRaises(c.ReconcileError):
                    self.api.inventory('tunnels')

    def test_mixed_ui_management_405_has_actionable_diagnostic(self):
        self.api.netskope.request = Mock(return_value=response(status=405, body={'status': 405}))
        with self.assertRaises(c.ReconcileError) as raised:
            self.api.inventory('tunnels')
        self.assertIn('API-managed', str(raised.exception))

    def test_request_counts_include_retries_and_reset(self):
        self.api.netskope.request = Mock(side_effect=[response(status=503), self.page([1], 1)])
        self.api.mist.request = Mock(return_value=response(body={'vars': {}}))
        with patch.object(c.time, 'sleep'):
            self.api.inventory('pops')
        self.api.setting('site1')
        self.assertEqual(self.api.reset_request_counts(), {'mist': 1, 'netskope': 2})
        self.assertEqual(self.api.request_counts, {'mist': 0, 'netskope': 0})


class RequestBudgetTests(unittest.TestCase):
    def test_projection_warns_only_near_the_budget(self):
        self.assertIsNone(c.request_budget_warning({'mist': 100}, 600, 5000))
        self.assertIn('Projected', c.request_budget_warning({'mist': 700}, 600, 5000))
        self.assertIsNone(c.request_budget_warning({}, 600, 5000))

    def test_steady_state_pass_avoids_redundant_template_reads(self):
        case = fixtures.LifecycleTests('test_creation_repeated_events_and_rename')
        case.setUp()
        try:
            case.success()
            reads = []
            original = case.api.template
            case.api.template = lambda template_id: reads.append(template_id) or original(template_id)
            case.success()
            self.assertLessEqual(len(reads), 3)
            self.assertEqual(case.api.calls, ['create', 'patch', 'put'])
        finally:
            case.tearDown()


class StateHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def open(self, binding=None):
        state = c.LifecycleState(self.root, binding or {'org': 'org'})
        self.addCleanup(state.close)
        return state

    def test_failed_start_releases_lock_and_database(self):
        self.open().close()
        with self.assertRaises(c.ReconcileError):
            c.LifecycleState(self.root, {'org': 'other'})
        self.open()  # Would raise "Another worker" if the failed start leaked its lock.

    def test_corrupt_database_is_a_controlled_error_and_releases_lock(self):
        (self.root / 'state.sqlite3').write_bytes(b'not a database' * 100)
        os.chmod(self.root / 'state.sqlite3', 0o600)
        with self.assertRaises(c.ReconcileError) as raised:
            c.LifecycleState(self.root, {'org': 'org'})
        self.assertIn('restore', str(raised.exception))
        (self.root / 'state.sqlite3').rename(self.root / 'corrupt.bak')
        self.open()

    def test_symlinked_state_artefacts_are_refused(self):
        target = self.root / 'elsewhere'
        target.write_text('')
        for name in ('worker.lock', 'state.sqlite3', 'state.sqlite3-wal'):
            with self.subTest(name=name):
                link = self.root / name
                link.symlink_to(target)
                with self.assertRaises(c.ReconcileError):
                    c.LifecycleState(self.root, {'org': 'org'})
                link.unlink()
        self.open()

    def test_database_and_lock_are_private(self):
        self.open()
        for name in ('worker.lock', 'state.sqlite3'):
            self.assertEqual((self.root / name).stat().st_mode & 0o777, 0o600, name)

    def test_secret_symlink_and_malformed_key_are_refused(self):
        state = self.open()
        for key in ('../escape', 'short', 'A' * 64, KEY + '/x'):
            with self.subTest(key=key), self.assertRaises(c.ReconcileError):
                state.secret(key, create=True)
        self.assertEqual(list((self.root / 'secrets').iterdir()) if (self.root / 'secrets').exists() else [], [])
        target = self.root / 'planted'
        target.write_text('x' * 64)
        os.chmod(target, 0o600)
        (self.root / 'secrets').mkdir(mode=0o700, exist_ok=True)
        (self.root / 'secrets' / (KEY + '.psk')).symlink_to(target)
        with self.assertRaises(c.ReconcileError):
            state.secret(KEY, create=True)

    def test_secret_is_stable_private_and_directory_synced(self):
        state = self.open()
        with patch.object(c.os, 'fsync', wraps=os.fsync) as fsync:
            first = state.secret(KEY, create=True)
        self.assertEqual(fsync.call_count, 2)  # File, then its directory entry.
        self.assertEqual(state.secret(KEY, create=True), first)
        self.assertEqual((self.root / 'secrets' / (KEY + '.psk')).stat().st_mode & 0o777, 0o600)

    def test_record_cache_is_isolated_and_write_through(self):
        state = self.open()
        state.save(KEY, {'site_id': 's1', 'template_id': 'tpl', 'status': 'configured'})
        state.save('b' * 64, {'site_id': 's2', 'template_id': 'tpl', 'status': 'deleted'})
        state.save('c' * 64, {'site_id': 's3', 'template_id': 'other', 'status': 'configured'})
        state.records()[KEY]['status'] = 'tampered'
        state.record(KEY)['status'] = 'tampered'
        self.assertEqual(state.record(KEY)['status'], 'configured')
        self.assertEqual(state.record('missing'), {})
        self.assertEqual(list(state.template_records('tpl')), [KEY])
        self.assertEqual(state.template_records('tpl', exclude_key=KEY), {})
        state.close()
        reopened = self.open()
        self.assertEqual(reopened.record(KEY)['status'], 'configured')
        self.assertEqual(len(reopened.records()), 3)

    def test_failed_save_does_not_poison_the_cache(self):
        state = self.open()
        state.save(KEY, {'site_id': 's1', 'status': 'configured'})
        with self.assertRaises(TypeError):
            state.save(KEY, {'site_id': 's1', 'status': object()})
        self.assertEqual(state.record(KEY)['status'], 'configured')

    def test_aggregate_enqueue_is_all_or_nothing(self):
        state = self.open()
        with patch.object(c, 'INBOX_CAPACITY', 2):
            state.enqueue('d1')
            with self.assertRaises(c.ReconcileError):
                state.enqueue_many(['d1', 'd2', 'd3'])
            self.assertEqual(state.pending(), ['d1'])
            state.enqueue_many(['d1', 'd2', 'd2'])
        self.assertEqual(sorted(state.pending()), ['d1', 'd2'])


class ReceiverTests(unittest.TestCase):
    secret = 'w' * 32

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = c.LifecycleState(self.temp.name, {'org': 'org'})
        self.addCleanup(self.state.close)
        self.wake = threading.Event()

    def serve(self, max_workers=c.WEBHOOK_MAX_WORKERS):
        server = c.BoundedWebhookServer(('127.0.0.1', 0), c.webhook_handler(self.state, 'org', self.secret, self.wake),
                                        max_workers=max_workers)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05})
        thread.start()

        def stop():
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        self.addCleanup(stop)
        return server

    def post(self, server, body, signature=None, timeout=5):
        signature = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest() if signature is None else signature
        client = HTTPConnection(*server.server_address, timeout=timeout)
        try:
            client.putrequest('POST', '/webhooks/mist')
            client.putheader('Content-Length', str(len(body)))
            client.putheader('X-Mist-Signature-v2', signature)
            client.endheaders(body)
            reply = client.getresponse()
            reply.read()
            return reply.status
        finally:
            client.close()

    def audit(self, *ids):
        return json.dumps({'topic': 'audits', 'events': [{'org_id': 'org', 'id': i} for i in ids]}).encode()

    def test_stalled_client_does_not_block_other_deliveries(self):
        server = self.serve()
        stalled = socket.create_connection(server.server_address)
        self.addCleanup(stalled.close)
        stalled.sendall(b'POST /webhooks/mist HTTP/1.1\r\nContent-Length: 100\r\n')  # Never completes.
        self.assertEqual(self.post(server, self.audit('one')), 202)
        self.assertTrue(self.wake.is_set())
        self.assertEqual(len(self.state.pending()), 1)

    def test_worker_cap_sheds_excess_connections_then_recovers(self):
        server = self.serve(max_workers=1)
        stalled = socket.create_connection(server.server_address)
        stalled.sendall(b'POST /webhooks/mist HTTP/1.1\r\n')
        deadline = threading.Event()
        for _ in range(100):  # Wait until the stalled connection holds the only slot.
            if not server._slots.acquire(blocking=False):
                break
            server._slots.release()
            deadline.wait(0.02)
        with self.assertRaises((OSError, HTTPException)):
            self.post(server, self.audit('shed'), timeout=2)
        self.assertEqual(self.state.pending(), [])
        stalled.close()
        for _ in range(100):
            if server._slots.acquire(blocking=False):
                server._slots.release()
                break
            deadline.wait(0.02)
        self.assertEqual(self.post(server, self.audit('after')), 202)

    def test_silent_connection_releases_its_slot_after_the_socket_timeout(self):
        with patch.object(c, 'WEBHOOK_SOCKET_TIMEOUT', 0.3):
            server = self.serve(max_workers=1)  # Handler class captures the patched timeout.
        silent = socket.create_connection(server.server_address)
        self.addCleanup(silent.close)
        waiter = threading.Event()
        for _ in range(100):
            waiter.wait(0.05)
            if server._slots.acquire(blocking=False):
                server._slots.release()
                try:
                    if self.post(server, self.audit('after-idle')) == 202:
                        return
                except (OSError, HTTPException):
                    continue
        self.fail('idle connection never released its worker slot')

    def test_enqueue_after_close_is_retryable_not_a_client_error(self):
        state = c.LifecycleState(tempfile.mkdtemp(), {'org': 'org'})
        state.close()
        with self.assertRaises(c.ReconcileError):
            state.enqueue('digest')
        with self.assertRaises(c.ReconcileError):
            state.pending()

    def test_non_ascii_or_malformed_signature_is_unauthorised_not_a_crash(self):
        server = self.serve()
        for signature in ('café', '', 'sha256=abc'):
            with self.subTest(signature=signature):
                self.assertEqual(self.post(server, self.audit('x'), signature=signature), 401)
        self.assertEqual(self.state.pending(), [])

    def test_full_inbox_rejects_whole_aggregate_with_503(self):
        server = self.serve()
        with patch.object(c, 'INBOX_CAPACITY', 1):
            self.assertEqual(self.post(server, self.audit('one', 'two')), 503)
        self.assertEqual(self.state.pending(), [])
        self.assertFalse(self.wake.is_set())


class OperatorCliTests(unittest.TestCase):
    """One-shot CLI paths driven end to end against the synthetic API."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / 'lifecycle.json'
        self.config_path.write_text(json.dumps(fixtures.config()))
        self.api = fixtures.FakeAPI()
        self.api.close = Mock()
        self.binding = {'org': 'org', 'netskope': ENV['NETSKOPE_TENANT_URL'], 'mist': ENV['MIST_BASE_URL']}

    def run_cli(self, *extra):
        argv = ['--lifecycle-config', str(self.config_path), '--state-dir', str(self.root / 'state'), *extra]
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, ENV, clear=False), patch.object(c, 'LifecycleAPI', return_value=self.api), \
                redirect_stdout(out), redirect_stderr(err):
            code = c.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_profile_digest_needs_no_credentials_or_state(self):
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(c.main(['--lifecycle-config', str(self.config_path), '--profile-digest']), 0)
        self.assertEqual(out.getvalue().strip(), c.fingerprint(fixtures.config()['profiles']))
        self.assertFalse((self.root / 'state').exists())

    def test_default_run_is_a_read_only_plan(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)[0]['action'], 'create')
        self.assertEqual(self.api.calls, [])
        self.api.close.assert_called_once_with()

    def test_apply_and_dry_run_conflict(self):
        code, _, err = self.run_cli('--apply', '--dry-run')
        self.assertEqual(code, 1)
        self.assertIn('--apply or --dry-run', err)
        self.assertEqual(self.api.calls, [])

    def test_apply_status_and_error_exit_code(self):
        code, out, _ = self.run_cli('--apply')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)[0]['status'], 'configured')
        code, out, _ = self.run_cli('--status')
        record = next(iter(json.loads(out).values()))
        self.assertEqual(record['status'], 'configured')
        self.assertNotIn('psk', out.lower())
        self.api.templates.clear()
        code, out, _ = self.run_cli('--apply')
        self.assertEqual(code, 1)

    def test_malformed_config_file_is_a_controlled_error(self):
        self.config_path.write_text('{not json')
        code, _, err = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn('lifecycle configuration', err)

    def pending_create(self):
        self.api.create = Mock(side_effect=c.ReconcileError('timeout'))
        self.assertEqual(self.run_cli('--apply')[0], 1)
        state = c.LifecycleState(self.root / 'state', self.binding)
        try:
            (key, record), = state.records().items()
        finally:
            state.close()
        self.assertEqual(record['status'], 'create_pending')
        return key

    def test_resolve_create_requires_confirmation_and_stopped_service(self):
        key = self.pending_create()
        for extra in ([], ['--confirm-no-remote-tunnel', '--apply'], ['--confirm-no-remote-tunnel', '--serve']):
            with self.subTest(extra=extra):
                self.assertEqual(self.run_cli('--resolve-create', key, *extra)[0], 1)
        self.assertEqual(self.run_cli('--resolve-create', 'f' * 64, '--confirm-no-remote-tunnel')[0], 1)

    def test_resolve_create_refuses_when_a_remote_tunnel_exists(self):
        key = self.pending_create()
        self.api.tunnels = [{'id': 9, 'site': 'mist-' + key[:24], 'notes': 'someone else'}]
        code, _, err = self.run_cli('--resolve-create', key, '--confirm-no-remote-tunnel')
        self.assertEqual(code, 1)
        self.assertIn('remote tunnel exists', err)

    def test_resolve_create_resets_locally_without_vendor_writes(self):
        key = self.pending_create()
        code, out, _ = self.run_cli('--resolve-create', key, '--confirm-no-remote-tunnel')
        self.assertEqual(code, 0)
        self.assertIn('no vendor write', out)
        self.assertEqual(self.api.calls, [])
        del self.api.create  # Restore the class implementation; the next apply may POST once.
        code, out, _ = self.run_cli('--apply')
        self.assertEqual(code, 0)
        self.assertEqual(self.api.calls.count('create'), 1)


class RetirementInventoryTests(unittest.TestCase):
    def test_missing_journalled_tunnel_needs_a_second_complete_read(self):
        case = fixtures.LifecycleTests('test_creation_repeated_events_and_rename')
        case.setUp()
        try:
            case.success()
            case.api.site_rows = []
            case.success()
            case.now += 61
            real, reads = case.api.inventory, []

            def flaky(resource):
                reads.append(resource)
                rows = real(resource)
                # The pass's first tunnel listing misses the row; the confirmation read sees it.
                return [] if resource == 'tunnels' and reads.count('tunnels') == 1 else rows
            case.api.inventory = flaky
            self.assertEqual(case.success()[0]['status'], 'deleted')
            self.assertEqual(case.api.calls.count('delete'), 1)  # Found on re-read, so actually deleted.
            self.assertEqual(case.api.tunnels, [])
        finally:
            case.tearDown()


class ShutdownTests(unittest.TestCase):
    def test_stop_request_abandons_pass_between_sites_without_writes(self):
        case = fixtures.LifecycleTests('test_creation_repeated_events_and_rename')
        case.setUp()
        try:
            case.worker.should_stop = lambda: True
            with self.assertRaises(c.ReconcileError):
                case.worker.reconcile()
            self.assertEqual(case.api.calls, [])
            self.assertEqual(case.state.records(), {})
        finally:
            case.tearDown()

    def test_abandoned_pass_leaves_inbox_pending(self):
        case = fixtures.LifecycleTests('test_creation_repeated_events_and_rename')
        case.setUp()
        try:
            case.state.enqueue('digest')
            case.worker.should_stop = lambda: True
            with self.assertRaises(c.ReconcileError):
                c.reconcile_cycle(case.worker, case.state)
            self.assertEqual(case.state.pending(), ['digest'])
        finally:
            case.tearDown()

    @unittest.skipUnless(threading.current_thread() is threading.main_thread(), 'signals need the main thread')
    def test_sigterm_stops_service_cleanly_and_reports_requests(self):
        previous = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in previous.items()])
        api = Mock()
        api.reset_request_counts.return_value = {'mist': 4000, 'netskope': 2}

        def cycle(reconciler, state):
            os.kill(os.getpid(), signal.SIGTERM)
            return []
        with tempfile.TemporaryDirectory() as root:
            config_path = Path(root) / 'lifecycle.json'
            config_path.write_text(json.dumps(fixtures.config()))
            argv = ['--lifecycle-config', str(config_path), '--state-dir', str(Path(root) / 'state'), '--serve', '--port', '0']
            env = dict(ENV, MIST_WEBHOOK_SECRET='s' * 32)
            with patch.dict(os.environ, env, clear=False), patch.object(c, 'LifecycleAPI', return_value=api), \
                    patch.object(c, 'reconcile_cycle', side_effect=cycle), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(c.main(argv), 0)
            # The lock is released: a new worker can start on the same directory.
            c.LifecycleState(Path(root) / 'state', {'org': 'org', 'netskope': ENV['NETSKOPE_TENANT_URL'],
                                                    'mist': ENV['MIST_BASE_URL']}).close()
        line = json.loads(out.getvalue().strip().splitlines()[-1])
        self.assertEqual(line['requests'], {'mist': 4000, 'netskope': 2})
        self.assertIn('warning', line)
        api.close.assert_called_once_with()

    def test_short_webhook_secret_is_refused_before_listening(self):
        with tempfile.TemporaryDirectory() as root:
            config_path = Path(root) / 'lifecycle.json'
            config_path.write_text(json.dumps(fixtures.config()))
            argv = ['--lifecycle-config', str(config_path), '--state-dir', str(Path(root) / 'state'), '--serve', '--port', '0']
            with patch.dict(os.environ, dict(ENV, MIST_WEBHOOK_SECRET='short'), clear=False), \
                    patch.object(c, 'LifecycleAPI', return_value=Mock()), redirect_stderr(io.StringIO()):
                self.assertEqual(c.main(argv), 1)


if __name__ == '__main__':
    unittest.main()
