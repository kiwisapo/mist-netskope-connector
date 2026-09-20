# Shared synthetic fixtures exercise provisioning and recovery without vendor access.
import copy
import hashlib
import hmac
import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import netskope_mist_connector as c


class FakeAPI:
    def __init__(self):
        self.cfg = SimpleNamespace(mist_org_id='org')
        self.site_rows = [{'id': 'site1', 'org_id': 'org', 'name': 'Branch', 'gatewaytemplate_id': 'tpl'}]
        self.settings = {'site1': {'vars': {'netskope_profile': 'srx', 'template_id': 'tpl', 'wan_ip': '192.0.2.10'}}}
        self.templates = {'tpl': {'name': 'Template', 'tunnels': {'unrelated': {'peer': '192.0.2.9'}}}}
        self.tunnels = []
        self.calls = []
        self.pops = [{'id': name, 'name': name, 'gateway': ip, 'probeip': ip, 'acceptingtunnels': True,
                      'bandwidth': '50 mbps', 'options': {'phase1': {'encryptionalgo': 'AES256-CBC', 'integrityalgo': 'SHA256', 'dhgroup': '14', 'salifetime': '8h', 'ikeversion': '2'}, 'phase2': {'encryptionalgo': 'AES256-CBC', 'integrityalgo': 'SHA256', 'dhgroup': '14', 'salifetime': '2h', 'pfs': True}}}
                     for name, ip in [('p1', '192.0.2.1'), ('p2', '192.0.2.2')]]
        self.lose_create_response = False
        self.fail_put = False
        self.inventory_failure = False

    def sites(self):
        if self.inventory_failure:
            raise c.ReconcileError('Mist HTTP 403')
        return copy.deepcopy(self.site_rows)

    def site(self, site_id):
        return next((copy.deepcopy(s) for s in self.site_rows if s['id'] == site_id), None)

    def setting(self, site_id):
        return copy.deepcopy(self.settings[site_id])

    def template(self, template_id):
        return copy.deepcopy(self.templates.get(template_id)), 'etag'

    def put_template(self, template_id, payload, etag):
        self.calls.append('put')
        self.templates[template_id].update(copy.deepcopy(payload))
        if self.fail_put:
            raise c.ReconcileError('Mist transport failure')

    def inventory(self, resource):
        return copy.deepcopy(self.tunnels if resource == 'tunnels' else self.pops)

    def create(self, payload):
        self.calls.append('create')
        tunnel = copy.deepcopy(payload)
        tunnel.pop('psk')  # Real APIs can hide secrets.
        tunnel['id'] = len(self.tunnels) + 1
        self.tunnels.append(tunnel)
        if self.lose_create_response:
            raise c.ReconcileError('Netskope transport failure')

    def update(self, tunnel_id, payload):
        self.calls.append('patch')
        for tunnel in self.tunnels:
            if tunnel['id'] == tunnel_id:
                tunnel.update(copy.deepcopy(payload))
                tunnel.pop('psk')

    def delete(self, tunnel_id):
        self.calls.append('delete')
        self.tunnels = [t for t in self.tunnels if t['id'] != tunnel_id]


def config():
    data = {'version': 1, 'cleanup_enabled': True, 'deletion_grace_seconds': 60,
            'profiles': {'srx': {'connections': [{
                'id': 'wan1', 'template_id': '${vars.template_id}',
                'crypto': {'phase1': {'encryptionalgo': 'AES256-CBC', 'integrityalgo': 'SHA256', 'dhgroup': '14', 'lifetime_seconds': 28800, 'ikeversion': '2'}, 'phase2': {'encryptionalgo': 'AES256-CBC', 'integrityalgo': 'SHA256', 'dhgroup': '14', 'lifetime_seconds': 7200, 'pfs': True}},
                'netskope': {'pops': ['p1', 'p2'], 'srcidentity': '${site.id}', 'srcipidentity': '${vars.wan_ip}',
                            'vendor': 'lab', 'template': 'lab', 'bandwidth': 50, 'encryption': 'AES256-CBC', 'sourcetype': 'Mixed'},
                'mist_entries': [{'path': ['tunnels', '${tunnel.name}'], 'value': {
                    'peer': '${primary.gateway}', 'backup': '${secondary.gateway}', 'psk': '${secret}'}}]
            }]}}}
    data['validation'] = {'evidence': 'synthetic test only', 'profiles_sha256': c.fingerprint(data['profiles'])}
    return data


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = c.LifecycleState(self.temp.name, {'org': 'org'})
        self.api = FakeAPI()
        self.config = config()
        self.now = 1000
        self.worker = c.Reconciler(self.api, self.state, self.config, apply=True, clock=lambda: self.now)

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def success(self):
        result = self.worker.reconcile()
        self.assertFalse([r for r in result if r.get('status') == 'error'], result)
        return result

    def test_creation_repeated_events_and_rename(self):
        self.success()
        self.assertEqual(self.api.calls, ['create', 'patch', 'put'])
        self.api.site_rows[0]['name'] = 'Renamed'
        self.success()
        self.assertEqual(self.api.calls, ['create', 'patch', 'put'])
        entry = next(v for k, v in self.api.templates['tpl']['tunnels'].items() if k != 'unrelated')
        self.assertGreaterEqual(len(entry['psk']), 32)
        self.assertNotIn(entry['psk'], json.dumps(self.state.records()))

    def test_dry_run_has_no_vendor_writes_or_ownership_records(self):
        self.worker.apply = False
        self.success()
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.state.records(), {})

    def test_missing_template_prevents_create(self):
        self.api.templates.clear()
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])

    def test_create_timeout_recovers_without_second_post(self):
        self.api.lose_create_response = True
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.success()
        self.assertEqual(self.api.calls.count('create'), 1)

    def test_uncertain_create_with_no_remote_match_does_not_retry(self):
        self.api.create = Mock(side_effect=c.ReconcileError('timeout'))
        self.worker.reconcile()
        self.worker.reconcile()
        self.assertEqual(self.api.create.call_count, 1)

    def test_restart_recovers_committed_create(self):
        self.api.lose_create_response = True
        self.worker.reconcile()
        self.state.close()
        self.state = c.LifecycleState(self.temp.name, {'org': 'org'})
        self.worker.state = self.state
        self.success()
        self.assertEqual(self.api.calls.count('create'), 1)

    def test_mist_timeout_after_applied_write_recovers(self):
        self.api.fail_put = True
        self.worker.reconcile()
        self.api.fail_put = False
        self.success()
        self.assertEqual(self.api.calls.count('put'), 1)

    def test_source_ip_drift_updates_existing_tunnel(self):
        self.success()
        self.api.settings['site1']['vars']['wan_ip'] = '192.0.2.11'
        self.success()
        self.assertEqual(self.api.calls.count('create'), 1)
        self.assertEqual(self.api.tunnels[0]['srcipidentity'], '192.0.2.11')

    def test_cleanup_requires_two_observations_and_preserves_unrelated_entries(self):
        self.success()
        self.api.site_rows = []
        self.assertEqual(self.success()[0]['status'], 'retirement_pending')
        self.assertNotIn('delete', self.api.calls)
        self.now += 61
        self.assertEqual(self.success()[0]['status'], 'deleted')
        self.assertEqual(self.api.templates['tpl']['tunnels'], {'unrelated': {'peer': '192.0.2.9'}})
        self.assertEqual(self.api.tunnels, [])
        self.success()
        self.assertEqual(self.api.calls.count('delete'), 1)

    def test_incomplete_inventory_cannot_delete(self):
        self.success()
        self.api.inventory_failure = True
        with self.assertRaises(c.ReconcileError):
            self.worker.reconcile()
        self.assertNotIn('delete', self.api.calls)

    def test_reappearing_site_resets_grace_even_when_ineligible(self):
        self.success()
        site = self.api.site_rows.pop()
        self.success()
        self.now += 61
        self.api.site_rows = [site]
        self.api.settings['site1']['vars'].clear()
        self.success()
        self.api.site_rows = []
        self.assertEqual(self.success()[0]['status'], 'retirement_pending')
        self.assertNotIn('delete', self.api.calls)

    def test_external_edit_blocks_cleanup(self):
        self.success()
        key = next(k for k in self.api.templates['tpl']['tunnels'] if k != 'unrelated')
        self.api.templates['tpl']['tunnels'][key]['peer'] = '192.0.2.99'
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotIn('delete', self.api.calls)

    def test_unowned_collision_blocks_before_create(self):
        key = self.worker.key('site1', 'wan1')
        self.api.templates['tpl']['tunnels']['mist-' + key[:24]] = {'peer': 'manual'}
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])

    def test_invalidated_profile_cannot_apply(self):
        self.config['profiles']['srx']['connections'][0]['netskope']['vendor'] = 'changed'
        with self.assertRaises(c.ReconcileError):
            self.worker.reconcile()
        self.assertEqual(self.api.calls, [])

    def test_masked_secret_readback_does_not_loop_and_allows_cleanup(self):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['secret_readback'] = 'masked'
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        original = self.api.template
        def masked(template_id):
            document, etag = original(template_id)
            for entry in document.get('tunnels', {}).values():
                if 'psk' in entry:
                    entry['psk'] = '********'
            return document, etag
        self.api.template = masked
        self.success()
        self.success()
        self.assertEqual(self.api.calls.count('put'), 1)
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.success()
        self.assertEqual(self.api.calls.count('delete'), 1)

    def test_masked_secret_uncertain_write_is_not_falsely_acknowledged(self):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['secret_readback'] = 'masked'
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        self.success()
        key = self.worker.key('site1', 'wan1')
        (Path(self.temp.name) / 'secrets' / (key + '.psk')).write_text('z' * 40)
        original = self.api.put_template
        self.api.put_template = Mock(side_effect=c.ReconcileError('failed before write'))
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.api.put_template = original
        self.success()
        entry = next(v for k, v in self.api.templates['tpl']['tunnels'].items() if k != 'unrelated')
        self.assertEqual(entry['psk'], 'z' * 40)

    def test_secret_rotation_updates_both_sides(self):
        self.success()
        key = self.worker.key('site1', 'wan1')
        (Path(self.temp.name) / 'secrets' / (key + '.psk')).write_text('n' * 40)
        self.success()
        self.assertEqual(self.api.calls.count('patch'), 2)
        self.assertEqual(self.api.calls.count('put'), 2)

    def test_shared_template_is_rejected_before_any_write(self):
        self.api.site_rows.append({'id': 'site2', 'org_id': 'org', 'gatewaytemplate_id': 'tpl'})
        self.api.settings['site2'] = {'vars': {}}
        result = self.worker.reconcile()
        self.assertEqual(result[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])

    def test_template_assignment_mismatch_is_rejected(self):
        self.api.site_rows[0]['gatewaytemplate_id'] = 'different'
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])

    def test_secondary_crypto_mismatch_prevents_create(self):
        self.api.pops[1]['options']['phase1']['dhgroup'] = '19'
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])

    def test_cleanup_disabled_preserves_remote_resources(self):
        self.success()
        self.config['cleanup_enabled'] = False
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.assertEqual(self.success()[0]['status'], 'cleanup_disabled')
        self.assertNotIn('delete', self.api.calls)

    def test_template_concurrent_edit_prevents_put(self):
        original = self.api.template
        calls = []
        def changing(template_id):
            calls.append(1)
            document, etag = original(template_id)
            if len(calls) == 4:
                document['name'] = 'Someone changed this'
            return document, etag
        self.api.template = changing
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotIn('put', self.api.calls)

    def test_managed_tunnel_with_changed_owner_cannot_be_deleted(self):
        self.success()
        self.api.tunnels[0]['notes'] = 'manual'
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotIn('delete', self.api.calls)

    def test_pending_mist_write_is_removed_on_retirement(self):
        self.api.fail_put = True
        self.worker.reconcile()
        self.api.fail_put = False
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.assertEqual(self.success()[0]['status'], 'deleted')
        self.assertEqual(list(self.api.templates['tpl']['tunnels']), ['unrelated'])

    def test_profile_removal_does_not_mean_site_deletion(self):
        self.success()
        self.api.settings['site1']['vars'].clear()
        self.now += 10000
        self.success()
        self.assertNotIn('delete', self.api.calls)

    def test_health_is_separate_from_configuration(self):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['health_checks'] = [{'path': ['state'], 'equals': 'up'}]
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        self.assertEqual(self.success()[0]['health'], 'unknown')
        self.api.tunnels[0]['state'] = 'up'
        self.assertEqual(self.success()[0]['health'], 'up')
        self.api.tunnels[0]['state'] = 'down'
        self.assertEqual(self.success()[0]['health'], 'down')

    def test_unowned_masked_secret_blocks_section_replay(self):
        self.api.templates['tpl']['tunnels']['unrelated']['psk'] = '********'
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])

    def test_multiple_wans_keep_distinct_keys_with_masked_readback(self):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['secret_readback'] = 'masked'
        second = copy.deepcopy(connection)
        second['id'] = 'wan2'
        self.config['profiles']['srx']['connections'].append(second)
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        original = self.api.template
        def masked(template_id):
            document, etag = original(template_id)
            for entry in document.get('tunnels', {}).values():
                if 'psk' in entry:
                    entry['psk'] = '********'
            return document, etag
        self.api.template = masked
        self.success()
        self.success()
        self.assertEqual(self.api.calls.count('create'), 2)
        keys = [value['psk'] for value in self.api.templates['tpl']['tunnels'].values() if 'psk' in value]
        self.assertEqual(len(set(keys)), 2)
        self.assertNotIn('********', keys)
        self.assertEqual(self.api.calls.count('put'), 2)

    def test_webhook_wrong_org_does_not_enqueue(self):
        server = c.BoundedWebhookServer(('127.0.0.1', 0), c.webhook_handler(self.state, 'org', 'x' * 32, threading.Event()))
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        try:
            body = json.dumps({'topic': 'audits', 'events': [{'org_id': 'other'}]}).encode()
            signature = hmac.new(('x' * 32).encode(), body, hashlib.sha256).hexdigest()
            client = HTTPConnection(*server.server_address)
            client.request('POST', '/webhooks/mist', body, {'X-Mist-Signature-v2': signature})
            response = client.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
            client.close()
            self.assertEqual(self.state.pending(), [])
        finally:
            thread.join(timeout=2)
            server.server_close()

    def test_inbox_is_acknowledged_only_after_successful_reconciliation(self):
        self.state.enqueue('event-1')
        self.api.fail_put = True
        c.reconcile_cycle(self.worker, self.state)
        self.assertEqual(self.state.pending(), ['event-1'])
        self.api.fail_put = False
        c.reconcile_cycle(self.worker, self.state)
        self.assertEqual(self.state.pending(), [])
        self.assertEqual(self.api.calls.count('create'), 1)

    def test_scheduled_pass_recovers_changes_without_webhook(self):
        self.assertEqual(self.state.pending(), [])
        c.reconcile_cycle(self.worker, self.state)
        self.assertEqual(self.api.calls.count('create'), 1)
        self.api.site_rows = []
        c.reconcile_cycle(self.worker, self.state)
        self.now += 61
        c.reconcile_cycle(self.worker, self.state)
        self.assertEqual(self.api.calls.count('delete'), 1)

    def test_event_arriving_during_a_pass_remains_pending(self):
        self.state.enqueue('before')
        fake = Mock()
        def reconcile():
            self.state.enqueue('during')
            return []
        fake.reconcile.side_effect = reconcile
        c.reconcile_cycle(fake, self.state)
        self.assertEqual(self.state.pending(), ['during'])

    def test_state_cannot_be_used_by_two_workers(self):
        with self.assertRaises(c.ReconcileError):
            c.LifecycleState(self.temp.name, {'org': 'org'})

    def test_signed_webhook_aggregates_and_deduplicates(self):
        wake = threading.Event()
        secret = 'x' * 32
        server = c.BoundedWebhookServer(('127.0.0.1', 0), c.webhook_handler(self.state, 'org', secret, wake))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            body = json.dumps({'topic': 'audits', 'events': [{'org_id': 'org', 'id': 'one'}, {'org_id': 'org', 'id': 'two'}]}).encode()
            signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            for supplied, code in [('bad', 401), (signature, 202), (signature, 202)]:
                connection = HTTPConnection(*server.server_address)
                connection.request('POST', '/webhooks/mist', body, {'X-Mist-Signature-v2': supplied})
                response = connection.getresponse()
                self.assertEqual(response.status, code)
                response.read()
                connection.close()
            self.assertEqual(len(self.state.pending()), 2)
            self.assertTrue(wake.is_set())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class HelperTests(unittest.TestCase):
    def test_duration_options_and_redaction(self):
        self.assertEqual(c.parse_duration_to_seconds('8h'), 28800)
        self.assertEqual(c.parse_csv_options('a, b'), ['a', 'b'])
        self.assertEqual(c.parse_bandwidth_tiers('50 mbps, 1 gbps'), [50, 1000])
        with self.assertRaises(ValueError):
            c.parse_duration_to_seconds('invalid')

    def test_typed_placeholders_and_no_interpolation(self):
        self.assertEqual(c.render({'enable': '${flag}'}, {'flag': True}), {'enable': True})
        with self.assertRaises(c.ReconcileError):
            c.render('prefix-${flag}', {'flag': True})


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.api = c.LifecycleAPI(SimpleNamespace(mist_base_url='https://mist.invalid', netskope_tenant_url='https://netskope.invalid',
                                                 mist_api_token='fake', netskope_api_token='fake', mist_org_id='org'))

    def test_netskope_truncated_list_fails_closed(self):
        self.api.request = Mock(return_value=({'result': [{'id': 1}], 'total': 2}, {}))
        with self.assertRaises(c.ReconcileError):
            self.api.inventory('tunnels')

    def test_mist_pagination_does_not_silently_truncate(self):
        self.api.request = Mock(side_effect=[([{'id': str(i), 'org_id': 'org'} for i in range(1000)], {}),
                                            ([{'id': 'last', 'org_id': 'org'}], {})])
        self.assertEqual(len(self.api.sites()), 1001)

    def test_repeated_mist_page_fails_closed(self):
        self.api.request = Mock(return_value=([{'id': str(i), 'org_id': 'org'} for i in range(1000)], {}))
        with self.assertRaises(c.ReconcileError):
            self.api.sites()

    def test_mutation_500_is_not_retried(self):
        self.api.netskope.request = Mock(return_value=SimpleNamespace(status_code=500))
        with self.assertRaises(c.ReconcileError):
            self.api.create({})
        self.assertEqual(self.api.netskope.request.call_count, 1)


if __name__ == '__main__':
    unittest.main()
