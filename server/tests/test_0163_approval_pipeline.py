import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Release0163ApprovalPipelineTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding='utf-8')

    def test_foreground_approval_uses_rule_worker_then_local_system_installer(self):
        text = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        self.assertIn('GenerateAsync("primary_allow"', text)
        self.assertIn('Install-GeneratedPolicy.ps1', text)
        self.assertNotIn('New-PrimaryApprovalPolicy.ps1', text)
        self.assertIn('QueueBackgroundBundle', text)
        self.assertNotIn('Building and installing the Windows App Control policy for {files.Length} file(s)', text)

    def test_foreground_primary_path_is_single_file(self):
        helper = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        primary_script = self.text('windows-agent/scripts/New-WorkerPolicy.ps1')
        self.assertIn('primaryFile', helper)
        self.assertIn("ValidateSet('primary_allow','deny_policy')", primary_script)
        self.assertIn('GenerateAsync("primary_allow", primaryFile', helper)
        foreground_section = helper[helper.index('ApproveFilesAsync'):helper.index('ExpandProtectedApplicationBundles')]
        self.assertNotIn('JsonSerializer.Serialize(files)', foreground_section)

    def test_primary_policy_prefers_product_name_filepublisher_for_safe_signed_file(self):
        generation = self.text('windows-agent/scripts/New-WorkerPolicy.ps1')
        install = self.text('windows-agent/scripts/Install-GeneratedPolicy.ps1')
        self.assertIn('SpecificFileNameLevel ProductName', generation)
        self.assertIn('Test-AppGuardProductFamilyCandidate', generation)
        self.assertIn('ACM_STAGE worker-policy-generation', generation)
        self.assertIn('ACM_STAGE generated-policy-install', install)

    def test_background_queue_is_durable_and_has_required_states(self):
        model = self.text('windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs')
        store = self.text('windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs')
        paths = self.text('windows-agent/src/AppGuard.Core/Paths.cs')
        for state in ('queued', 'processing', 'ready', 'installed', 'superseded', 'failed'):
            self.assertIn(state, model.lower())
        self.assertIn('BackgroundPolicyQueuePath', paths)
        self.assertIn('RuleFragmentDirectory', paths)
        self.assertIn('product|', model)
        self.assertIn('hash|', model)
        self.assertIn('MinimumFileVersion', model)
        self.assertIn('Owners', model)
        self.assertIn('.tmp.', store)
        self.assertIn('File.Move', store)

    def test_background_work_runs_in_a_separate_loop_and_is_serialized_with_foreground(self):
        worker = self.text('windows-agent/src/AppGuard.Service/AgentWorker.cs')
        helper = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        self.assertIn('RunBackgroundPolicyLoopAsync', worker)
        self.assertIn('Task.WhenAll', worker)
        self.assertIn('SemaphoreSlim', helper)
        self.assertIn('foreground', helper.lower())

    def test_auxiliary_grouping_is_same_root_same_signer_and_product_aware(self):
        helper = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        self.assertIn('NormalizePublisher', helper)
        self.assertIn('ProductName', helper)
        self.assertIn('ApplicationRoot', helper)
        self.assertIn('RuleKey', helper)
        self.assertIn('IsSameOrDescendantRoot', helper)
        self.assertIn('UpsertProductCandidate', helper)
        self.assertIn('UpsertHashCandidate', helper)
        self.assertIn('QueueBundle', helper)

    def test_scoped_policy_id_propagates_from_command_into_background_bundle(self):
        worker = self.text('windows-agent/src/AppGuard.Service/AgentWorker.cs')
        helper = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        self.assertIn('scoped_policy_id', worker)
        self.assertIn('ApproveFilesAsync(sources, sessionRequestId, sessionScopedPolicyId, ct)', worker)
        self.assertIn('QueueBackgroundBundle(requestId, scopedPolicyId', helper)

    def test_background_fragment_generation_does_not_install_policy(self):
        text = self.text('windows-agent/scripts/New-RuleFragment.ps1')
        self.assertIn('New-CIPolicyRule', text)
        self.assertIn('New-CIPolicy', text)
        self.assertNotIn('CiTool.exe --update-policy', text)
        self.assertNotIn('ConvertFrom-CIPolicy', text)

    def test_background_processor_is_one_item_per_iteration(self):
        text = self.text('windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs')
        self.assertIn('ProcessOneAsync', text)
        self.assertIn('ClaimNextRule', text)
        self.assertIn('ClaimReadyBundle', text)
        self.assertIn('ForegroundPending', text)
        self.assertIn('ReportBackgroundPolicyAsync', text)

    def test_request_bundle_install_merges_cached_fragments_into_one_supplemental(self):
        text = self.text('windows-agent/scripts/Install-MergedSupplemental.ps1')
        self.assertIn('Merge-CIPolicy', text)
        self.assertIn('ConvertFrom-CIPolicy', text)
        self.assertIn('CiTool.exe --update-policy', text)
        self.assertIn('ACM_STAGE background-policy-install', text)

    def test_learning_event_upload_queues_reusable_rule_candidates_after_successful_upload(self):
        worker = self.text('windows-agent/src/AppGuard.Service/AgentWorker.cs')
        store = self.text('windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs')
        upload = worker[worker.index('private async Task UploadEventsAsync'):worker.index('private async Task ProcessCommandsAsync')]
        self.assertIn('EventId == 3076', upload)
        self.assertIn('PolicyInspector.GetMode()', upload)
        self.assertIn('learning', upload.lower())
        self.assertIn('PrepareLearningEvents', upload)
        self.assertIn('UpsertProductCandidate', store)
        self.assertIn('UpsertHashCandidate', store)
        self.assertIn('UpsertLearningReference', store)
        self.assertIn('learning-prep observed=', upload)
        self.assertLess(upload.index('UploadEventsAsync(chunk'), upload.index('PrepareLearningEvents'))

    def test_learning_enforcement_consumes_prepared_fragments_and_only_generates_delta(self):
        text = self.text('windows-agent/scripts/End-LearningAndEnforce.ps1')
        helper = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        store = self.text('windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs')
        self.assertIn('Install-LearnedBaselineFromFragments.ps1', text)
        self.assertIn('ACM_STAGE learned-final-delta', text)
        self.assertIn('prepared=', text)
        self.assertIn('unprepared=', text)
        self.assertNotIn('New-LearnedBaselinePolicy.ps1', text)
        self.assertIn('Get-LearnedApplications.ps1', helper)
        self.assertIn('LearningRuleKeysForPaths', store)
        self.assertIn('GenerateRuleFragmentForegroundAsync', helper)
        self.assertIn('FragmentListPath', helper)

    def test_learned_baseline_replacement_removes_old_baseline_only_after_new_install(self):
        text = self.text('windows-agent/scripts/Install-LearnedBaselineFromFragments.ps1')
        install = text.index('CiTool.exe --update-policy')
        verify = text.index('Installed learned baseline')
        remove = text.index('--remove-policy')
        self.assertLess(install, verify)
        self.assertLess(verify, remove)
        self.assertIn('AppControl Manager Learned Baseline', text)
        self.assertIn('ACM_STAGE learned-baseline-merge', text)
        self.assertIn('ACM_STAGE learned-baseline-install', text)
        self.assertIn('ACM_STAGE learned-baseline-cleanup', text)
        self.assertIn('stale learned-baseline policies removed', text)

    def _app_with_temp_db(self):
        server_dir = ROOT / 'server'
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module
        fd, path = tempfile.mkstemp(prefix='acm-0163-', suffix='.db')
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, 'DB_PATH', old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def test_background_schema_and_heartbeat_columns_are_additive(self):
        app_module, path = self._app_with_temp_db()
        with sqlite3.connect(path) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn('approval_background_policies', tables)
            device_columns = {row[1] for row in conn.execute('PRAGMA table_info(devices)')}
            for column in ('background_policy_status', 'background_policy_pending', 'background_policy_failed'):
                self.assertIn(column, device_columns)
        self.assertNotIn('DROP TABLE', self.text('server/app.py'))

    def test_device_detail_surfaces_background_policy_work(self):
        text = self.text('server/app.py')
        self.assertIn('Background Policy Work', text)
        self.assertIn('background_policy_pending', text)
        self.assertIn('background_policy_failed', text)

    def test_heartbeat_persists_background_queue_diagnostics(self):
        app_module, path = self._app_with_temp_db()
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at) VALUES(?,?,?,?,?)", ('d1','pc1','x','0.16.3',now))
            conn.commit()
        app_module.heartbeat(app_module.HeartbeatRequest(
            learning_mode=False, policy_mode='enforcement',
            background_policy_status='processing', background_policy_pending=3, background_policy_failed=1,
        ), 'd1')
        with sqlite3.connect(path) as conn:
            row = conn.execute('SELECT background_policy_status,background_policy_pending,background_policy_failed FROM devices WHERE id=?', ('d1',)).fetchone()
        self.assertEqual(row, ('processing', 3, 1))

    def test_foreground_command_inventory_records_only_primary_file(self):
        app_module, path = self._app_with_temp_db()
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at) VALUES(?,?,?,?,?)", ('d1','pc1','x','0.12.0',now))
            cur = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at,component_count,request_kind) VALUES(?,?,?,?,?,?)", ('d1',r'C:\\Apps\\main.exe','approving',now,2,'session'))
            request_id = cur.lastrowid
            conn.execute("INSERT INTO approval_request_items(request_id,original_path,product_name) VALUES(?,?,?)", (request_id,r'C:\\Apps\\main.exe','Main App'))
            conn.execute("INSERT INTO approval_request_items(request_id,original_path,product_name) VALUES(?,?,?)", (request_id,r'C:\\Apps\\helper.dll','Main App'))
            payload = json.dumps({'request_id': request_id, 'components': [{'file_path': r'C:\\Apps\\main.exe'}, {'file_path': r'C:\\Apps\\helper.dll'}]})
            cmd = conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)", ('d1','approve_session',payload,'processing',now)).lastrowid
            conn.commit()
        app_module.complete_command(cmd, app_module.CommandComplete(success=True, policy_id='11111111-1111-1111-1111-111111111111', file_path=r'C:\\Apps\\main.exe', product_name='Main App'), 'd1')
        with sqlite3.connect(path) as conn:
            rows = conn.execute('SELECT file_path FROM approved_components WHERE request_id=? ORDER BY id', (request_id,)).fetchall()
        self.assertEqual([r[0] for r in rows], [r'C:\\Apps\\main.exe'])

    def test_background_report_installs_auxiliary_inventory_without_reopening_request(self):
        app_module, path = self._app_with_temp_db()
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at) VALUES(?,?,?,?,?)", ('d1','pc1','x','0.16.3',now))
            request_id = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at,decision_note) VALUES(?,?,?,?,?)", ('d1',r'C:\\Apps\\main.exe','approved',now,'Primary authorization installed.')).lastrowid
            conn.commit()
        report = app_module.BackgroundPolicyReport(
            request_id=request_id, status='installed', policy_id='22222222-2222-2222-2222-222222222222', detail='Background application coverage installed.',
            components=[app_module.ApprovalComponentIn(file_path=r'C:\\Apps\\helper.dll', product_name='Helper')],
        )
        app_module.report_background_policy(report, 'd1')
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            request = conn.execute('SELECT status,decision_note FROM approval_requests WHERE id=?', (request_id,)).fetchone()
            bg = conn.execute('SELECT status,policy_id FROM approval_background_policies WHERE request_id=?', (request_id,)).fetchone()
            components = conn.execute('SELECT file_path,policy_id FROM approved_components WHERE request_id=?', (request_id,)).fetchall()
        self.assertEqual(request['status'], 'approved')
        self.assertEqual(bg['status'], 'installed')
        self.assertEqual(bg['policy_id'], '22222222-2222-2222-2222-222222222222')
        self.assertEqual([(r['file_path'], r['policy_id']) for r in components], [(r'C:\\Apps\\helper.dll', '22222222-2222-2222-2222-222222222222')])

    def test_background_failure_does_not_revoke_primary_approval(self):
        app_module, path = self._app_with_temp_db()
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at) VALUES(?,?,?,?,?)", ('d1','pc1','x','0.16.3',now))
            request_id = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at,decision_note) VALUES(?,?,?,?,?)", ('d1',r'C:\\Apps\\main.exe','approved',now,'Primary authorization installed.')).lastrowid
            conn.commit()
        report = app_module.BackgroundPolicyReport(request_id=request_id, status='failed', detail='ConfigCI failed')
        app_module.report_background_policy(report, 'd1')
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            request = conn.execute('SELECT status FROM approval_requests WHERE id=?', (request_id,)).fetchone()
            bg = conn.execute('SELECT status,detail FROM approval_background_policies WHERE request_id=?', (request_id,)).fetchone()
        self.assertEqual(request['status'], 'approved')
        self.assertEqual(bg['status'], 'failed')
        self.assertIn('ConfigCI failed', bg['detail'])

    def test_background_server_schema_is_additive_and_tracks_linked_policy_ids(self):
        text = self.text('server/app.py')
        self.assertIn('CREATE TABLE IF NOT EXISTS approval_background_policies', text)
        self.assertIn('/api/background-policies/report', text)
        self.assertIn('background_policy_status', text)
        self.assertNotIn('DROP TABLE', text)

    def test_linked_policy_ids_for_request_collects_primary_component_and_background_layers(self):
        app_module, path = self._app_with_temp_db()
        now = app_module.utcnow()
        primary = '11111111-1111-1111-1111-111111111111'
        auxiliary = '22222222-2222-2222-2222-222222222222'
        background = '33333333-3333-3333-3333-333333333333'
        unrelated = '44444444-4444-4444-4444-444444444444'
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at) VALUES(?,?,?,?,?)", ('d1','pc1','x','0.16.3',now))
            request_id = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at) VALUES(?,?,?,?)", ('d1',r'C:\\Apps\\main.exe','approved',now)).lastrowid
            unrelated_request = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at) VALUES(?,?,?,?)", ('d1',r'C:\\Other\\other.exe','approved',now)).lastrowid
            conn.execute("INSERT INTO approved_applications(device_id,request_id,file_path,policy_id,approved_at,status) VALUES(?,?,?,?,?,?)", ('d1',request_id,r'C:\\Apps\\main.exe',primary,now,'approved'))
            conn.execute("INSERT INTO approved_components(device_id,request_id,file_path,policy_id,approved_at,status) VALUES(?,?,?,?,?,?)", ('d1',request_id,r'C:\\Apps\\helper.dll',auxiliary,now,'approved'))
            conn.execute("INSERT INTO approved_components(device_id,request_id,file_path,policy_id,approved_at,status) VALUES(?,?,?,?,?,?)", ('d1',request_id,r'C:\\Apps\\placeholder.dll','command-123',now,'approved'))
            conn.execute("INSERT INTO approval_background_policies(device_id,request_id,policy_id,status,created_at,completed_at) VALUES(?,?,?,?,?,?)", ('d1',request_id,background,'installed',now,now))
            conn.execute("INSERT INTO approved_components(device_id,request_id,file_path,policy_id,approved_at,status) VALUES(?,?,?,?,?,?)", ('d1',unrelated_request,r'C:\\Other\\other.exe',unrelated,now,'approved'))
            conn.commit()
            conn.row_factory = sqlite3.Row
            ids = app_module.linked_policy_ids_for_request(conn, 'd1', request_id)
        self.assertEqual(set(ids), {primary.upper(), auxiliary.upper(), background.upper()})

    def test_revoke_completion_keeps_request_approved_until_all_linked_layers_are_removed(self):
        app_module, path = self._app_with_temp_db()
        now = app_module.utcnow()
        primary = '11111111-1111-1111-1111-111111111111'
        background = '33333333-3333-3333-3333-333333333333'
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at) VALUES(?,?,?,?,?)", ('d1','pc1','x','0.12.0',now))
            request_id = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at) VALUES(?,?,?,?)", ('d1',r'C:\\Apps\\main.exe','approved',now)).lastrowid
            conn.execute("INSERT INTO approved_applications(device_id,request_id,file_path,policy_id,approved_at,status) VALUES(?,?,?,?,?,?)", ('d1',request_id,r'C:\\Apps\\main.exe',primary,now,'revoking'))
            conn.execute("INSERT INTO approval_background_policies(device_id,request_id,policy_id,status,created_at,completed_at) VALUES(?,?,?,?,?,?)", ('d1',request_id,background,'installed',now,now))
            cmd1 = conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)", ('d1','revoke_approval',json.dumps({'policy_id':primary,'requested_by':'admin'}),'processing',now)).lastrowid
            conn.commit()
        app_module.complete_command(cmd1, app_module.CommandComplete(success=True, result='removed'), 'd1')
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute('SELECT status FROM approval_requests WHERE id=?',(request_id,)).fetchone()[0], 'approved')
            conn.execute("UPDATE approval_background_policies SET status='revoking' WHERE request_id=?", (request_id,))
            cmd2 = conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)", ('d1','revoke_approval',json.dumps({'policy_id':background,'requested_by':'admin'}),'processing',now)).lastrowid
            conn.commit()
        app_module.complete_command(cmd2, app_module.CommandComplete(success=True, result='removed'), 'd1')
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute('SELECT status FROM approval_requests WHERE id=?',(request_id,)).fetchone()[0], 'revoked')
            self.assertEqual(conn.execute('SELECT status FROM approval_background_policies WHERE request_id=?',(request_id,)).fetchone()[0], 'revoked')

    def test_revoke_queues_all_policy_layers_linked_to_same_request(self):
        text = self.text('server/app.py')
        self.assertIn('linked_policy_ids_for_request', text)
        self.assertIn('queue_linked_policy_revocations', text)
        self.assertIn('approval_background_policies', text)

    def test_revoke_routes_use_linked_policy_revocation_helper(self):
        text = self.text('server/app.py')
        revoke_section = text[text.index('def revoke_approved'):text.index('@app.post("/admin/approved/{component_id}/block")')]
        disable_section = text[text.index("def disable_policy"):text.index("@app.post('/admin/policies/{policy_id}/delete')")]
        self.assertIn('queue_linked_policy_revocations', revoke_section)
        self.assertIn('queue_linked_policy_revocations', disable_section)

    def test_user_visible_background_states_do_not_replace_primary_approval_status(self):
        server = self.text('server/app.py')
        helper = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        self.assertIn('request_background_status', server)
        self.assertIn('Approved — background application coverage is still processing', server)
        self.assertIn('Bundle ready', server)
        self.assertIn('Background coverage failed; primary approval remains installed', server)
        self.assertIn('Authorizing primary application...', helper)
        self.assertIn('"authorizing_primary"', helper)
        self.assertIn('"approved"', helper)

    def test_rollback_baseline_is_documented(self):
        features = self.text('0.16.3-FEATURES.txt') if (ROOT / '0.16.3-FEATURES.txt').exists() else ''
        self.assertIn('0.16.2', features)
        self.assertIn('rollback', features.lower())


if __name__ == '__main__':
    unittest.main()
