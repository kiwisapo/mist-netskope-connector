# Contract fixtures document captured assumptions, not current live API compatibility.
"""Contract tests derived from the tenant's OpenAPI 3.0.1 document (18 Sep 2026).

The document itself is a tenant export kept out of the repository; the shapes
below are transcribed from its ``ipsec_*`` schemas. These tests prove the
reconciler converges against the documented *read* shape, which differs from
the *write* shape. They do not prove tenant behaviour beyond the document."""
import copy
import tempfile
import unittest
import unittest.mock
from types import SimpleNamespace
from unittest.mock import Mock

import netskope_mist_connector as c
import test_lifecycle as fixtures


class SpecShapedAPI(fixtures.FakeAPI):
    """FakeAPI whose tunnel reads follow ``ipsec_tunnel_result_item``."""
    def __init__(self):
        super().__init__()
        for pop, name in zip(self.pops, ('syd1', 'mel1')):
            pop['name'] = name  # IDs stay p1/p2 so profiles may use either.

    def _stored(self, payload):
        row = copy.deepcopy(payload)
        row.pop('psk', None)                       # Never returned on reads.
        row['enabled'] = row.pop('enable', True)   # Read shape uses ``enabled``.
        by_id = {p['name']: p for p in self.pops}
        row['pops'] = [{'name': by_id[i]['name'], 'gateway': by_id[i]['gateway'], 'probeip': by_id[i]['probeip'],
                        'primary': n == 0, 'status': 'up', 'since': '1781356550', 'throughput': '0.68 Kbps'}
                       for n, i in enumerate(payload['pops'])]
        if isinstance(row.get('options'), dict) and isinstance(row['options'].get('xff'), dict):
            xff = dict(row['options']['xff'])
            xff['enabled'] = xff.pop('enable', False)
            xff.setdefault('iplist', [])
            # Tenant-added defaults observed on 18 Sep 2026.
            row['options'] = {**row['options'], 'xff': xff, 'qos': {'enabled': False, 'linkid': 0}, 'ctap': False}
        row['version'] = 2
        return row

    def create(self, payload):
        self.calls.append('create')
        row = self._stored(payload)
        row['id'] = len(self.tunnels) + 1
        self.tunnels.append(row)

    def update(self, tunnel_id, payload):
        self.calls.append('patch')
        for n, tunnel in enumerate(self.tunnels):
            if tunnel['id'] == tunnel_id:
                merged = {**{k: v for k, v in tunnel.items() if k not in ('enabled', 'pops', 'options')}, **payload}
                merged.setdefault('enable', tunnel.get('enabled', True))
                self.tunnels[n] = {**self._stored(merged), 'id': tunnel_id}


def options_config():
    config = fixtures.config()
    config['profiles']['srx']['connections'][0]['netskope']['options'] = {
        'reauth': False, 'rekey': False, 'xff': {'enable': False}}
    config['validation']['profiles_sha256'] = c.fingerprint(config['profiles'])
    return config


class ReadShapeConvergenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = c.LifecycleState(self.temp.name, {'org': 'org'})
        self.addCleanup(self.state.close)
        self.api = SpecShapedAPI()
        self.worker = c.Reconciler(self.api, self.state, options_config(), apply=True)

    def success(self):
        result = self.worker.reconcile()
        self.assertFalse([r for r in result if r.get('status') == 'error'], result)
        return result

    def test_documented_read_shape_converges_without_a_patch_loop(self):
        self.success()
        self.assertEqual(self.api.calls, ['create', 'patch', 'put'])  # First PATCH carries the key digest.
        self.success()
        self.success()
        self.assertEqual(self.api.calls, ['create', 'patch', 'put'])
        tunnel = self.api.tunnels[0]
        self.assertIn('enabled', tunnel)
        self.assertNotIn('enable', tunnel)
        self.assertEqual({p['name'] for p in tunnel['pops']}, {'syd1', 'mel1'})

    def test_pop_change_is_detected_through_names(self):
        self.success()
        self.api.pops.append({**copy.deepcopy(self.api.pops[1]), 'id': 'p3', 'name': 'bne1', 'gateway': '192.0.2.3'})
        self.worker.config['profiles']['srx']['connections'][0]['netskope']['pops'] = ['p1', 'p3']
        self.worker.config['validation']['profiles_sha256'] = c.fingerprint(self.worker.config['profiles'])
        self.success()
        self.assertEqual(self.api.calls.count('patch'), 2)
        self.assertEqual({p['name'] for p in self.api.tunnels[0]['pops']}, {'syd1', 'bne1'})

    def test_external_disable_is_corrected(self):
        self.success()
        self.api.tunnels[0]['enabled'] = False
        self.success()
        self.assertEqual(self.api.calls.count('patch'), 2)
        self.assertTrue(self.api.tunnels[0]['enabled'])


class TunnelMatchTests(unittest.TestCase):
    desired = {'site': 's', 'enable': True, 'pops': ['p1', 'p2'], 'bandwidth': 50,
               'options': {'reauth': False, 'rekey': False, 'xff': {'enable': False}}, 'psk': 'k'}
    names = {'p1': 'syd1', 'p2': 'mel1'}

    def observed(self, **overrides):
        row = {'site': 's', 'enabled': True, 'bandwidth': 50, 'version': 2,
               'pops': [{'name': 'mel1', 'primary': False}, {'name': 'syd1', 'primary': True}],
               'options': {'reauth': False, 'rekey': False, 'xff': {'enabled': False, 'iplist': []},
                           'qos': {'enabled': False, 'linkid': 0}, 'ctap': False}}
        row.update(overrides)
        return row

    def test_spec_read_shape_matches_desired_write_payload(self):
        self.assertTrue(c.Reconciler.tunnel_matches(self.observed(), self.desired, self.names))

    def test_differences_are_still_detected(self):
        for overrides in ({'enabled': False}, {'bandwidth': 100},
                          {'pops': [{'name': 'syd1'}, {'name': 'bne1'}]}, {'pops': [{'name': 'syd1'}]},
                          {'options': {'reauth': True, 'rekey': False, 'xff': {'enabled': False, 'iplist': []}}},
                          {'options': {'reauth': False, 'rekey': False, 'xff': {'enabled': True, 'iplist': []}}}):
            with self.subTest(overrides=overrides):
                self.assertFalse(c.Reconciler.tunnel_matches(self.observed(**overrides), self.desired, self.names))

    def test_legacy_id_lists_and_missing_pops_are_handled(self):
        self.assertFalse(c.Reconciler.tunnel_matches(self.observed(pops=['p2', 'p1']), self.desired, self.names))
        self.assertTrue(c.Reconciler.tunnel_matches(self.observed(pops=['syd1', 'mel1']), self.desired, self.names))
        self.assertFalse(c.Reconciler.tunnel_matches(self.observed(pops=None), self.desired, self.names))
        self.assertFalse(c.Reconciler.tunnel_matches({}, self.desired, self.names))


class LiveTenantEvidenceTests(unittest.TestCase):
    """Behaviour observed against the development tenant on 18 Sep 2026."""
    def worker(self, mutate):
        case = fixtures.LifecycleTests('test_creation_repeated_events_and_rename')
        case.setUp()
        self.addCleanup(case.tearDown)
        mutate(case.worker.config['profiles']['srx']['connections'][0])
        case.worker.config['validation']['profiles_sha256'] = c.fingerprint(case.worker.config['profiles'])
        return case

    def test_invalid_sourcetype_and_null_encryption_are_rejected_before_any_write(self):
        for mutate, text in ((lambda conn: conn['netskope'].update(sourcetype='Site'), 'sourcetype'),
                             (lambda conn: conn['netskope'].update(encryption='Null'), 'Null'),
                             (lambda conn: conn['crypto']['phase2'].update(encryptionalgo='Null'), 'Null')):
            case = self.worker(mutate)
            for pop in case.api.pops:  # Tenant advertises Null in phase 2; the profile must still not select it.
                pop['options']['phase2']['encryptionalgo'] += ', Null'
            result = case.worker.reconcile()
            self.assertEqual(result[0]['status'], 'error', result)
            self.assertIn(text, result[0]['detail'])
            self.assertEqual(case.api.calls, [])

    def test_empty_xff_iplist_is_rejected_as_the_tenant_does(self):
        case = self.worker(lambda conn: conn['netskope'].update(options={'xff': {'enable': False, 'iplist': []}}))
        result = case.worker.reconcile()
        self.assertIn('iplist', result[0]['detail'])
        self.assertEqual(case.api.calls, [])

    def test_pops_are_sent_by_name_and_accepted_by_id_or_name(self):
        for refs in (['p1', 'p2'], ['syd1', 'mel1'], ['p1', 'mel1']):
            with self.subTest(refs=refs):
                case = self.worker(lambda conn, refs=refs: conn['netskope'].update(pops=refs))
                for pop, name in zip(case.api.pops, ('syd1', 'mel1')):
                    pop['name'] = name
                case.success()
                self.assertEqual(case.api.tunnels[0]['pops'], ['syd1', 'mel1'])

    def test_partial_patch_is_refused_by_the_transport(self):
        api = c.LifecycleAPI(SimpleNamespace(mist_base_url='https://mist.invalid', netskope_tenant_url='https://netskope.invalid',
                                             mist_api_token='fake', netskope_api_token='fake', mist_org_id='org'))
        api.netskope.request = Mock()
        with self.assertRaises(c.ReconcileError) as raised:
            api.update(1, {'bandwidth': 100})
        self.assertIn('encryption', str(raised.exception))
        api.netskope.request.assert_not_called()

    def test_netskope_calls_are_paced_and_exhausted_windows_are_honoured(self):
        api = c.LifecycleAPI(SimpleNamespace(mist_base_url='https://mist.invalid', netskope_tenant_url='https://netskope.invalid',
                                             mist_api_token='fake', netskope_api_token='fake', mist_org_id='org'))
        clock = [1000.0]
        with unittest.mock.patch.object(c.time, 'monotonic', side_effect=lambda: clock[0]), \
                unittest.mock.patch.object(c.time, 'sleep', side_effect=lambda s: clock.__setitem__(0, clock[0] + s)) as sleep:
            api.pace_netskope()
            api.pace_netskope()
            self.assertEqual([round(call.args[0], 2) for call in sleep.call_args_list], [0.25])
            api.note_netskope_limits({'RateLimit-Remaining': '0', 'RateLimit-Reset': '1'})
            api.pace_netskope()
            self.assertEqual(round(sleep.call_args_list[-1].args[0], 2), 1.0)
            api.note_netskope_limits({'RateLimit-Remaining': '0', 'RateLimit-Reset': '99'})
            api.pace_netskope()
            self.assertEqual(round(sleep.call_args_list[-1].args[0], 2), 5.0)
            api.note_netskope_limits({'RateLimit-Remaining': '3'})
            api.pace_netskope()
            self.assertEqual(round(sleep.call_args_list[-1].args[0], 2), 0.25)


class MistSpecTests(unittest.TestCase):
    """Derived from the official Mist OpenAPI 2607.1.1 document (no Mist org available)."""
    def test_section_write_always_carries_the_required_template_name(self):
        case = fixtures.LifecycleTests('test_creation_repeated_events_and_rename')
        case.setUp()
        try:
            payloads = []
            original = case.api.put_template
            case.api.put_template = lambda tid, payload, etag: payloads.append(payload) or original(tid, payload, etag)
            case.success()
            self.assertEqual(len(payloads), 1)
            self.assertEqual(payloads[0]['name'], 'Template')
            self.assertEqual(set(payloads[0]), {'name', 'tunnels'})  # Only the owned section plus the required name.
        finally:
            case.tearDown()

    def test_example_custom_ipsec_entry_renders_against_spec_shapes(self):
        import json
        from pathlib import Path
        config = json.loads(Path('examples/lifecycle.example.json').read_text())
        for platform in ('srx', 'ssr'):
            conn = config['profiles'][platform]['connections'][0]
            context = {'site': {'id': 's', 'gatewaytemplate_id': 't'}, 'setting': {}, 'owner': 'o', 'secret': 'k' * 43,
                       'vars': {'netskope_identity': 'branch1.example.invalid', 'netskope_wan_name': 'wan0'},
                       'tunnel': {'name': 'mist-abc'}, 'crypto': conn['crypto'],
                       'primary': {'gateway': '192.0.2.1', 'probeip': '198.51.100.1'},
                       'secondary': {'gateway': '192.0.2.2', 'probeip': '198.51.100.2'}}
            entry = c.render(conn['mist_entries'], context)[0]
            value = entry['value']
            self.assertEqual(entry['path'], ['tunnel_configs', 'mist-abc'])
            self.assertEqual(value['provider'], 'custom-ipsec')
            self.assertEqual(value['psk'], 'k' * 43)
            self.assertIsInstance(value['ike_lifetime'], int)  # Whole-value placeholders keep JSON types.
            self.assertEqual(value['primary']['hosts'], ['192.0.2.1'])
            self.assertEqual(value['secondary']['probe_ips'], ['198.51.100.2'])
            self.assertEqual(value['ike_proposals'][0]['dh_group'], conn['crypto']['phase1']['dhgroup'])
            self.assertIn('REPLACE_WITH_', value['networks'][0])  # Deployment-specific; blocks --apply until set.
            self.assertEqual(conn['netskope']['sourcetype'], 'Mixed')
            self.assertNotIn('iplist', conn['netskope']['options']['xff'])


class CapacityAndConflictTests(unittest.TestCase):
    def setUp(self):
        self.api = c.LifecycleAPI(SimpleNamespace(
            mist_base_url='https://mist.invalid', netskope_tenant_url='https://netskope.invalid',
            mist_api_token='fake', netskope_api_token='fake', mist_org_id='org'))

    def response(self, status=200, body=None):
        return SimpleNamespace(status_code=status, content=b'{}' if body is not None else b'', headers={}, json=lambda: body)

    def test_maxsites_is_captured_from_the_tunnel_listing_only(self):
        self.api.netskope.request = Mock(return_value=self.response(body={'status': 200, 'total': 1, 'maxsites': 200, 'result': [{'id': 1}]}))
        self.api.inventory('tunnels')
        self.assertEqual(self.api.tunnel_capacity, {'total': 1, 'maxsites': 200})
        self.api.netskope.request = Mock(return_value=self.response(body={'status': 200, 'total': 1, 'result': [{'id': 'p'}]}))
        self.api.inventory('pops')
        self.assertEqual(self.api.tunnel_capacity, {'total': 1, 'maxsites': 200})
        self.api.netskope.request = Mock(return_value=self.response(body={'status': 200, 'total': 0, 'maxsites': '200', 'result': []}))
        self.api.inventory('tunnels')
        self.assertEqual(self.api.tunnel_capacity, {'total': 0, 'maxsites': None})

    def test_exhausted_capacity_blocks_the_post(self):
        case = fixtures.LifecycleTests('test_creation_repeated_events_and_rename')
        case.setUp()
        try:
            case.api.tunnel_capacity = {'total': 200, 'maxsites': 200}
            result = case.worker.reconcile()
            self.assertEqual(result[0]['status'], 'error')
            self.assertIn('maxsites', result[0]['detail'])
            self.assertEqual(case.api.calls, [])
            self.assertEqual(case.state.records(), {})  # Nothing journalled: the check precedes create_pending.
            case.api.tunnel_capacity = {'total': 199, 'maxsites': 200}
            case.success()
            self.assertEqual(case.api.calls.count('create'), 1)
        finally:
            case.tearDown()

    def test_documented_conflict_and_forbidden_codes_have_clear_errors(self):
        self.api.netskope.request = Mock(return_value=self.response(status=409, body={'status': 409, 'result': 'exists'}))
        with self.assertRaises(c.ReconcileError) as raised:
            self.api.create({'site': 'x'})
        self.assertIn('already exists', str(raised.exception))
        self.api.netskope.request = Mock(return_value=self.response(status=403, body={'status': 403, 'result': 'no'}))
        with self.assertRaises(c.ReconcileError) as raised:
            self.api.inventory('pops')
        self.assertIn('403', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
