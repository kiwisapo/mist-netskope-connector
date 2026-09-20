# Regression coverage for ownership refresh, POP identity/roles and masked list secrets.
"""Regressions for cleanup ownership, POP roles and nested masked secrets."""
import copy
import unittest

from test_contract import SpecShapedAPI

import netskope_mist_connector as c
import test_lifecycle as fixtures


class ReviewRegressions(unittest.TestCase):
    setUp = fixtures.LifecycleTests.setUp
    tearDown = fixtures.LifecycleTests.tearDown
    success = fixtures.LifecycleTests.success

    def attest(self):
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])

    def prepare_retirement(self):
        self.success()
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.api.calls.clear()

    def test_changed_owner_after_snapshot_blocks_all_cleanup(self):
        self.prepare_retirement()
        original = self.api.sites
        reads = []

        def sites():
            reads.append(True)
            if len(reads) == 2:
                self.api.tunnels[0]['notes'] = 'another-owner'
            return original()

        self.api.sites = sites
        result = self.worker.reconcile()
        self.assertEqual(result[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])
        self.assertEqual(len(self.api.tunnels), 1)

    def test_changed_owner_during_mist_cleanup_blocks_delete(self):
        self.prepare_retirement()
        original = self.api.put_template

        def put(*args):
            original(*args)
            self.api.tunnels[0]['notes'] = 'another-owner'

        self.api.put_template = put
        result = self.worker.reconcile()
        self.assertEqual(result[0]['status'], 'error')
        self.assertEqual(self.api.calls, ['put'])
        self.assertEqual(len(self.api.tunnels), 1)
        self.assertNotEqual(next(iter(self.state.records().values()))['status'], 'deleted')

    def test_failed_fresh_inventory_prevents_cleanup(self):
        self.prepare_retirement()
        original = self.api.inventory
        reads = []

        def inventory(resource):
            if resource == 'tunnels':
                reads.append(True)
                if len(reads) == 2:
                    raise c.ReconcileError('inventory unavailable')
            return original(resource)

        self.api.inventory = inventory
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])

    def use_spec_api(self):
        self.api = SpecShapedAPI()
        self.worker.api = self.api

    def test_primary_swap_updates_both_vendors_and_converges(self):
        self.use_spec_api()
        self.success()
        self.api.calls.clear()
        self.config['profiles']['srx']['connections'][0]['netskope']['pops'] = ['p2', 'p1']
        self.attest()
        self.success()
        self.assertEqual(self.api.calls, ['patch', 'put'])
        self.assertEqual(next(p['name'] for p in self.api.tunnels[0]['pops'] if p['primary']), 'mel1')
        # The read API may return POP records in any order.
        self.api.tunnels[0]['pops'].reverse()
        self.success()
        self.assertEqual(self.api.calls, ['patch', 'put'])

    def test_pop_aliases_cannot_select_one_destination_twice(self):
        self.use_spec_api()
        self.config['profiles']['srx']['connections'][0]['netskope']['pops'] = ['p1', 'syd1']
        self.attest()
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.state.records(), {})
        self.assertEqual(list((self.state.root / 'secrets').glob('*.psk')), [])

    def test_ambiguous_pop_roles_do_not_match(self):
        desired = {'pops': ['syd1', 'mel1']}
        for flags in [(True, True), (False, False), (True, None), (1, False)]:
            with self.subTest(flags=flags):
                actual = {'pops': [{'name': name, 'primary': flag} for name, flag in zip(desired['pops'], flags)]}
                self.assertFalse(c.Reconciler.tunnel_matches(actual, desired))

    def prepare_nested_masking(self, second=False):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['secret_readback'] = 'masked'
        connection['mist_entries'][0]['value'] = {'peers': [{'psk': '${secret}', 'host': '${primary.gateway}'}]}
        if second:
            other = copy.deepcopy(connection)
            other['id'] = 'wan2'
            self.config['profiles']['srx']['connections'].append(other)
        self.attest()
        original = self.api.template

        def masked(template_id):
            document, etag = original(template_id)
            for entry in document.get('tunnels', {}).values():
                for peer in entry.get('peers', []):
                    peer['psk'] = '********'
            return document, etag

        self.api.template = masked

    def test_nested_masked_secrets_converge_restore_and_retire(self):
        self.prepare_nested_masking(second=True)
        self.success()
        self.success()
        self.assertEqual(self.api.calls.count('put'), 2)
        for key in self.state.records():
            value = self.api.templates['tpl']['tunnels']['mist-' + key[:24]]
            self.assertEqual(value['peers'][0]['psk'], self.state.secret(key))
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.success()
        self.assertEqual(self.api.calls.count('delete'), 2)
        self.assertEqual(self.api.templates['tpl']['tunnels'], {'unrelated': {'peer': '192.0.2.9'}})

    def test_nested_masked_lost_put_recovers_and_peer_drift_blocks(self):
        self.prepare_nested_masking()
        self.api.fail_put = True
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.api.fail_put = False
        self.success()
        before = list(self.api.calls)
        key = self.worker.key('site1', 'wan1')
        self.api.templates['tpl']['tunnels']['mist-' + key[:24]]['peers'][0]['host'] = 'external'
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, before)

    def test_nested_secret_shape_drift_fails_closed(self):
        paths = c.secret_paths({'peers': [{'psk': 'synthetic'}]}, 'synthetic')
        for value in ({'peers': []}, {'peers': {}}, {'peers': [None]}):
            with self.subTest(value=value), self.assertRaises(c.ReconcileError):
                c.entry_hash(value, paths)

    def test_secret_list_values_and_numeric_object_keys_remain_distinct(self):
        value = {'keys': ['synthetic'], '0': {'psk': 'synthetic'}}
        paths = c.secret_paths(value, 'synthetic')
        self.assertEqual(paths, [['keys', 0], ['0', 'psk']])
        masked = {'keys': ['********'], '0': {'psk': '********'}}
        self.assertEqual(c.entry_hash(value, paths), c.entry_hash(masked, paths))
        for path in paths:
            c.put_path(masked, path, 'synthetic')
        self.assertEqual(masked, value)
