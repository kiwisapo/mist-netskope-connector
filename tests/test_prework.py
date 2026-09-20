"""Offline acceptance for preservation, recovery, monitoring and state backups."""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import netskope_mist_connector as c
import test_lifecycle as fixtures


class PreworkTests(unittest.TestCase):
    setUp = fixtures.LifecycleTests.setUp
    tearDown = fixtures.LifecycleTests.tearDown
    success = fixtures.LifecycleTests.success

    def test_replacing_put_detected_and_remains_blocked_after_restart(self):
        self.api.templates['tpl']['unrelated_section'] = {'keep': True}
        def replacing(template_id, payload, etag):
            self.api.calls.append('put')
            self.api.templates[template_id] = copy.deepcopy(payload)
        self.api.put_template = replacing
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        before = list(self.api.calls)
        self.state.close()
        self.state = c.LifecycleState(self.temp.name, {'org': 'org'})
        self.worker.state = self.state
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, before)
        # Repairing the unrelated configuration permits normal recovery.
        self.api.templates['tpl']['unrelated_section'] = {'keep': True}
        self.success()

    def test_lost_put_cannot_hide_unrelated_loss(self):
        self.api.templates['tpl']['unrelated_section'] = {'keep': True}
        original = self.api.put_template
        def lost(*args):
            original(*args)
            self.api.templates['tpl'].pop('unrelated_section')
            raise c.ReconcileError('uncertain put')
        self.api.put_template = lost
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.api.put_template = original
        before = list(self.api.calls)
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, before)

    def test_preservation_ignores_metadata_and_new_owned_ancestors(self):
        original = self.api.put_template
        self.config['profiles']['srx']['connections'][0]['mist_entries'][0]['path'] = ['new_section', 'nested', '${tunnel.name}']
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        def put(*args):
            original(*args)
            self.api.templates['tpl']['modified_time'] = 123
        self.api.put_template = put
        self.success()
        self.success()

    def test_cleanup_preservation_loss_blocks_delete_and_retry(self):
        self.success()
        self.api.templates['tpl']['unrelated_section'] = {'keep': True}
        self.api.site_rows = []
        self.success()
        self.now += 61
        original = self.api.put_template
        def damaging(*args):
            original(*args)
            self.api.templates['tpl'].pop('unrelated_section', None)
        self.api.put_template = damaging
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotIn('delete', self.api.calls)
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotIn('delete', self.api.calls)

    def test_lost_patch_before_or_after_application_recovers(self):
        self.success()
        original = self.api.update
        for applied in (False, True):
            with self.subTest(applied=applied):
                self.api.settings['site1']['vars']['wan_ip'] = '192.0.2.' + ('12' if applied else '11')
                def lost(*args, applied=applied):
                    if applied:
                        original(*args)
                    raise c.ReconcileError('uncertain patch')
                self.api.update = lost
                self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
                self.api.update = original
                self.success()
                self.assertEqual(self.api.tunnels[0]['srcipidentity'], self.api.settings['site1']['vars']['wan_ip'])
        self.assertEqual(self.api.calls.count('create'), 1)

    def test_lost_delete_after_application_recovers_without_second_delete(self):
        self.success()
        self.api.site_rows = []
        self.success()
        self.now += 61
        original = self.api.delete
        def lost(*args):
            original(*args)
            raise c.ReconcileError('uncertain delete')
        self.api.delete = lost
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.api.delete = original
        self.assertEqual(self.success()[0]['status'], 'deleted')
        self.assertEqual(self.api.calls.count('delete'), 1)

    def test_lost_delete_before_application_retries_owned_tunnel(self):
        self.success()
        self.api.site_rows = []
        self.success()
        self.now += 61
        original = self.api.delete
        self.api.delete = Mock(side_effect=c.ReconcileError('lost before application'))
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(len(self.api.tunnels), 1)
        self.api.delete = original
        self.assertEqual(self.success()[0]['status'], 'deleted')

    def test_delete_visibility_lag_never_reports_deleted_early(self):
        self.success()
        self.api.site_rows = []
        self.success()
        self.now += 61
        self.api.delete = Mock()  # Acknowledged but the row remains visible.
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotEqual(next(iter(self.state.records().values()))['status'], 'deleted')
        self.api.tunnels.clear()
        self.assertEqual(self.success()[0]['status'], 'deleted')
        self.api.delete.assert_called_once()

    def test_duplicate_markers_block_further_mutation(self):
        self.success()
        second = copy.deepcopy(self.api.tunnels[0])
        second['id'] = 99
        self.api.tunnels.append(second)
        before = list(self.api.calls)
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertEqual(self.api.calls, before)

    def test_one_site_failure_does_not_block_another(self):
        self.api.site_rows.append({'id': 'site2', 'org_id': 'org', 'name': 'Second', 'gatewaytemplate_id': 'tpl2'})
        self.api.settings['site2'] = {'vars': {'netskope_profile': 'srx', 'template_id': 'tpl2', 'wan_ip': '192.0.2.11'}}
        self.api.templates['tpl2'] = {'name': 'Second'}
        del self.api.templates['tpl']
        results = self.worker.reconcile()
        self.assertEqual([r['status'] for r in results], ['error', 'configured'])

    def test_rotation_interrupted_between_vendors_recovers(self):
        self.success()
        key = self.worker.key('site1', 'wan1')
        self.state.root.joinpath('secrets', key + '.psk').write_text('r' * 40)
        original = self.api.put_template
        self.api.put_template = Mock(side_effect=c.ReconcileError('failed before put'))
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.api.put_template = original
        self.success()
        record = self.state.record(key)
        self.assertEqual(record['secret_hash'], record['mist_secret_hash'])
        self.assertEqual(self.api.templates['tpl']['tunnels']['mist-' + key[:24]]['psk'], 'r' * 40)

    def test_operational_status_tracks_success_failure_and_preview(self):
        c.reconcile_cycle(self.worker, self.state)
        good = self.state.operational_status()['last_pass']
        self.assertEqual(good['outcome'], 'success')
        self.assertEqual(good['health']['not_verified'], 1)
        self.api.inventory_failure = True
        with self.assertRaises(c.ReconcileError):
            c.reconcile_cycle(self.worker, self.state)
        bad = self.state.operational_status()['last_pass']
        self.assertEqual(bad['outcome'], 'error')
        self.assertEqual(bad['last_apply_success_at'], good['last_apply_success_at'])
        self.api.inventory_failure = False
        self.worker.apply = False
        c.reconcile_cycle(self.worker, self.state)
        preview = self.state.operational_status()['last_pass']
        self.assertFalse(preview['apply'])
        self.assertEqual(preview['last_apply_success_at'], good['last_apply_success_at'])
        self.assertGreaterEqual(preview['duration_seconds'], 0)

    def test_health_down_is_distinct_from_configuration_success(self):
        connection = self.config['profiles']['srx']['connections'][0]
        connection['health_checks'] = [{'path': ['enabled'], 'equals': True}]
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        c.reconcile_cycle(self.worker, self.state)
        # Fake API has no enabled field, hence unknown, not configuration failure.
        status = self.state.operational_status()
        self.assertEqual(status['last_pass']['outcome'], 'success')
        self.assertEqual(status['last_pass']['health']['unknown'], 1)
        self.assertEqual(next(iter(self.state.records().values()))['health'], 'unknown')

    def test_scheduled_retention_preserves_unresolved_events(self):
        self.state.enqueue_many(['done', 'pending'])
        self.state.acknowledge(['done'])
        with self.state.db:
            self.state.db.execute('UPDATE inbox SET created=?', (time.time() - c.INBOX_RETENTION_SECONDS - 1,))
        self.api.inventory_failure = True
        with self.assertRaises(c.ReconcileError):
            c.reconcile_cycle(self.worker, self.state)
        self.assertEqual(self.state.pending(), ['pending'])
        self.assertEqual(self.state.db.execute('SELECT COUNT(*) FROM inbox').fetchone()[0], 1)

    def test_status_never_persists_error_text(self):
        self.api.sites = Mock(side_effect=c.ReconcileError('synthetic-sensitive-value'))
        with self.assertRaises(c.ReconcileError):
            c.reconcile_cycle(self.worker, self.state)
        self.assertNotIn('synthetic-sensitive-value', json.dumps(self.state.operational_status()))

    def test_backup_restore_preserves_identity_keys_and_pending_work(self):
        self.success()
        self.state.enqueue('pending')
        with tempfile.TemporaryDirectory() as root:
            backup, restored_path = Path(root) / 'backup', Path(root) / 'restored'
            c.state_snapshot(self.state, backup)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            c.restore_snapshot(backup, restored_path, {'org': 'org'})
            restored = c.LifecycleState(restored_path, {'org': 'org'})
            try:
                self.assertEqual(restored.installation, self.state.installation)
                self.assertEqual(restored.records(), self.state.records())
                self.assertEqual(restored.pending(), ['pending'])
                for key in self.state.records():
                    self.assertEqual(restored.secret(key), self.state.secret(key))
                before = list(self.api.calls)
                worker = c.Reconciler(self.api, restored, self.config, apply=True)
                self.assertEqual(worker.reconcile()[0]['status'], 'configured')
                self.assertEqual(self.api.calls, before)
            finally:
                restored.close()

    def test_restore_rejects_corruption_wrong_binding_and_existing_target(self):
        self.success()
        with tempfile.TemporaryDirectory() as root:
            backup, target = Path(root) / 'backup', Path(root) / 'restored'
            c.state_snapshot(self.state, backup)
            with self.assertRaises(c.ReconcileError):
                c.restore_snapshot(backup, target, {'org': 'wrong'})
            self.assertFalse(target.exists())
            target.mkdir()
            sentinel = target / 'sentinel'
            sentinel.write_text('keep')
            with self.assertRaises(c.ReconcileError):
                c.restore_snapshot(backup, target, {'org': 'org'})
            self.assertEqual(sentinel.read_text(), 'keep')
            db = backup / 'state.sqlite3'
            db.write_bytes(b'corrupt')
            with self.assertRaises(c.ReconcileError):
                c.restore_snapshot(backup, Path(root) / 'corrupt', {'org': 'org'})

    def test_backup_failure_removes_partial_copy_and_preserves_existing(self):
        self.success()
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'backup'
            with patch.object(c.shutil, 'rmtree', wraps=c.shutil.rmtree) as cleanup, \
                    patch.object(self.state, 'secret', side_effect=c.ReconcileError('missing')):
                with self.assertRaises(c.ReconcileError):
                    c.state_snapshot(self.state, target)
                self.assertFalse(target.exists())
                cleanup.assert_called_once_with(target)
            target.mkdir()
            with self.assertRaises(c.ReconcileError):
                c.state_snapshot(self.state, target)
            self.assertTrue(target.exists())
            with self.assertRaises(c.ReconcileError):
                c.state_snapshot(self.state, self.state.root / 'backup')

    def test_restore_rejects_path_traversal_and_symlink(self):
        self.success()
        with tempfile.TemporaryDirectory() as root:
            backup = Path(root) / 'backup'
            c.state_snapshot(self.state, backup)
            manifest = backup / 'manifest.json'
            original = manifest.read_text()
            data = json.loads(original)
            data['files']['../outside'] = 'invalid'
            manifest.write_text(json.dumps(data))
            with self.assertRaises(c.ReconcileError):
                c.restore_snapshot(backup, Path(root) / 'target', {'org': 'org'})
            manifest.write_text(original)
            db = backup / 'state.sqlite3'
            db.unlink()
            db.symlink_to(self.state.root / 'state.sqlite3')
            with self.assertRaises(c.ReconcileError):
                c.restore_snapshot(backup, Path(root) / 'target', {'org': 'org'})

    def test_concurrent_edit_before_put_can_retry_without_preservation_latch(self):
        original = self.api.template
        reads = []
        def changed(template_id):
            reads.append(True)
            if len(reads) == 4:
                self.api.templates[template_id]['unrelated_new'] = True
            return original(template_id)
        self.api.template = changed
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotIn('pending_preservation', next(iter(self.state.records().values())))
        self.api.template = original
        self.success()
        self.assertTrue(self.api.templates['tpl']['unrelated_new'])

    def test_unresolved_write_blocks_other_connections_on_same_template(self):
        second = copy.deepcopy(self.config['profiles']['srx']['connections'][0])
        second['id'] = 'wan2'
        self.config['profiles']['srx']['connections'].append(second)
        self.config['validation']['profiles_sha256'] = c.fingerprint(self.config['profiles'])
        self.api.fail_put = True
        results = self.worker.reconcile()
        self.assertEqual([r['status'] for r in results], ['error', 'error'])
        self.assertEqual(self.api.calls.count('create'), 1)
        self.api.fail_put = False
        self.success()
        self.assertEqual(self.api.calls.count('create'), 2)

    def test_reappearing_site_recovers_interrupted_cleanup(self):
        self.success()
        sites = copy.deepcopy(self.api.site_rows)
        self.api.site_rows = []
        self.success()
        self.now += 61
        original = self.api.put_template
        def put(*args):
            original(*args)
            self.api.site_rows = sites
        self.api.put_template = put
        self.assertEqual(self.worker.reconcile()[0]['status'], 'error')
        self.assertNotIn('delete', self.api.calls)
        self.api.put_template = original
        self.success()
        record = next(iter(self.state.records().values()))
        self.assertNotIn('cleanup_preservation', record)
        self.assertEqual(record['status'], 'configured')


class MaintenanceCliTests(unittest.TestCase):
    def setUp(self):
        from test_optimisation import OperatorCliTests
        OperatorCliTests.setUp(self)

    def run_cli(self, *args):
        from test_optimisation import OperatorCliTests
        return OperatorCliTests.run_cli(self, *args)

    def test_cli_backup_status_restore_make_no_vendor_calls(self):
        self.assertEqual(self.run_cli('--apply')[0], 0)
        self.api.inventory = Mock(side_effect=AssertionError('No vendor reads allowed'))
        self.api.sites = Mock(side_effect=AssertionError('No vendor reads allowed'))
        code, output, _ = self.run_cli('--operational-status')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['last_pass']['outcome'], 'success')
        backup = self.root / 'backup'
        self.assertEqual(self.run_cli('--backup-state', str(backup))[0], 0)
        restored = self.root / 'restored'
        self.assertEqual(self.run_cli('--restore-state', str(backup), '--state-dir', str(restored))[0], 0)
        code, output, _ = self.run_cli('--status', '--state-dir', str(restored))
        self.assertEqual(code, 0)
        self.assertEqual(next(iter(json.loads(output).values()))['status'], 'configured')

    def test_maintenance_modes_refuse_ambiguous_or_live_combinations(self):
        for flags in [('--backup-state', str(self.root / 'backup'), '--apply'),
                      ('--restore-state', 'backup', '--serve'), ('--operational-status', '--status')]:
            with self.subTest(flags=flags):
                self.assertEqual(self.run_cli(*flags)[0], 1)
        self.assertEqual(self.api.calls, [])

    def test_backup_cannot_silently_create_fresh_state(self):
        self.assertEqual(self.run_cli('--backup-state', str(self.root / 'backup'))[0], 1)
        self.assertFalse((self.root / 'state').exists())

    def test_backup_requires_exclusive_worker_lock(self):
        state = c.LifecycleState(self.root / 'state', self.binding)
        try:
            self.assertEqual(self.run_cli('--backup-state', str(self.root / 'backup'))[0], 1)
            self.assertFalse((self.root / 'backup').exists())
        finally:
            state.close()
