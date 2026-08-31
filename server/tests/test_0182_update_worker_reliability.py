import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0182UpdateWorkerReliabilityTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_worker_request_is_published_only_after_job_permissions_are_ready(self):
        client = self.text("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        self.assertIn('var unpublishedRequestPath = Path.Combine(jobDirectory, "request.pending.json")', client)
        self.assertIn(
            "RuleWorkerProvisioner.GrantJobAccess(jobDirectory, stagedInput, unpublishedRequestPath)",
            client,
        )
        self.assertIn("File.Move(unpublishedRequestPath, requestPath, false)", client)
        self.assertLess(
            client.index("GrantJobAccess(jobDirectory, stagedInput, unpublishedRequestPath)"),
            client.index("File.Move(unpublishedRequestPath, requestPath, false)"),
        )

    def test_worker_failure_reporting_cannot_terminate_the_service_loop(self):
        service = self.text("windows-agent/src/AppGuard.Service/RuleWorkerService.cs")
        self.assertIn("ProcessJobSafelyAsync", service)
        self.assertIn("job result publication failed", service)
        self.assertIn("await ProcessJobSafelyAsync(jobDirectory, requestPath, resultPath", service)

    def test_worker_wait_is_bounded_and_checks_service_liveness(self):
        client = self.text("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        provisioner = self.text("windows-agent/src/AppGuard.Service/RuleWorkerProvisioner.cs")
        self.assertIn("WorkerResultTimeout = TimeSpan.FromMinutes(5)", client)
        self.assertNotIn("within 35 minutes", client)
        self.assertIn("EnsureRunning", provisioner)
        self.assertIn("RuleWorkerProvisioner.EnsureRunning()", client)

    def test_known_restrictive_store_option_is_accepted(self):
        validator = self.text("windows-agent/src/AppGuard.Core/WorkerPolicyValidator.cs")
        self.assertIn('"Required:Enforce Store Applications"', validator)

    def test_updater_preauthorizes_exact_hashes_for_both_replacement_binaries(self):
        updater = self.text("windows-agent/src/AppGuard.Service/AgentUpdater.cs")
        helper = self.text("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        self.assertIn("PreauthorizeAgentUpdateAsync([service, tray]", updater)
        self.assertIn("PreauthorizeAgentUpdateAsync", helper)
        self.assertIn("GenerateAsync(\"hash\"", helper)
        self.assertIn("Install-MergedSupplemental.ps1", helper)

    def test_failed_release_history_is_a_durable_retry_latch(self):
        app = self.text("server/app.py")
        self.assertIn("latest_release_failure", app)
        self.assertIn("release_id=? AND status IN ('failed','rolled_back')", app)

    def test_staging_heartbeat_cannot_requeue_a_release_that_already_failed(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, db_path = tempfile.mkstemp(prefix="acm-0182-update-", suffix=".db")
        os.close(fd)
        os.unlink(db_path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = db_path
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(db_path) and os.unlink(db_path))
        app_module.init_db()
        now = app_module.utcnow()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Org','org-0182','active',?)", (now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,desired_agent_version,update_status,created_at,organization_id) VALUES('d1','pc1','x','0.18.1','0.18.2','staging',?,99)", (now,))
            release_id = conn.execute("INSERT INTO agent_releases(version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES('0.18.2','stable','agent.zip','/tmp/agent.zip',?,1,1,?)", ('A' * 64, now)).lastrowid
            deployment_id = conn.execute("INSERT INTO agent_deployments(release_id,scope_type,scope_id,organization_id,rollout_percent,active,created_at) VALUES(?,'device','d1',99,100,1,?)", (release_id, now)).lastrowid
            conn.execute("INSERT INTO agent_update_history(device_id,release_id,deployment_id,from_version,target_version,status,created_at,completed_at) VALUES('d1',?,?,'0.18.1','0.18.2','failed',?,?)", (release_id, deployment_id, now, now))
            conn.commit()

            app_module.refresh_device_update_target(conn, "d1")
            queued = conn.execute("SELECT COUNT(*) FROM commands WHERE device_id='d1' AND command_type='update_agent'").fetchone()[0]
            device = conn.execute("SELECT update_status FROM devices WHERE id='d1'").fetchone()[0]

        self.assertEqual(0, queued)
        self.assertEqual("failed", device)

    def test_installing_history_prevents_overlapping_update_assignment(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, db_path = tempfile.mkstemp(prefix="acm-rc10-update-", suffix=".db")
        os.close(fd)
        os.unlink(db_path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = db_path
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(db_path) and os.unlink(db_path))
        app_module.init_db()
        now = app_module.utcnow()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Org','org-rc10','active',?)", (now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,desired_agent_version,update_status,created_at,organization_id) VALUES('d1','pc1','x','1.0.0-rc.9','1.0.0-rc.11','installing',?,99)", (now,))
            installing_release_id = conn.execute("INSERT INTO agent_releases(version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES('1.0.0-rc.10','stable','10.zip','/tmp/10.zip',?,1,1,?)", ('A' * 64, now)).lastrowid
            desired_release_id = conn.execute("INSERT INTO agent_releases(version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES('1.0.0-rc.11','stable','11.zip','/tmp/11.zip',?,1,1,?)", ('B' * 64, now)).lastrowid
            deployment_id = conn.execute("INSERT INTO agent_deployments(release_id,scope_type,scope_id,organization_id,rollout_percent,active,created_at) VALUES(?,'device','d1',99,100,1,?)", (desired_release_id, now)).lastrowid
            command_id = conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at,started_at,completed_at,result) VALUES('d1','update_agent','{}','completed',?,?,?,'Activation helper is starting.')", (now, now, now)).lastrowid
            conn.execute("INSERT INTO agent_update_history(device_id,release_id,deployment_id,command_id,from_version,target_version,status,created_at) VALUES('d1',?,?,?,'1.0.0-rc.9','1.0.0-rc.10','installing',?)", (installing_release_id, deployment_id, command_id, now))
            conn.commit()

            app_module.refresh_device_update_target(conn, "d1")
            queued = conn.execute("SELECT COUNT(*) FROM commands WHERE device_id='d1' AND command_type='update_agent' AND status='pending'").fetchone()[0]
            histories = conn.execute("SELECT COUNT(*) FROM agent_update_history WHERE device_id='d1'").fetchone()[0]

        self.assertEqual(0, queued)
        self.assertEqual(1, histories)

    def test_reported_version_releases_an_older_activation_latch(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, db_path = tempfile.mkstemp(prefix="acm-rc10-latch-", suffix=".db")
        os.close(fd)
        os.unlink(db_path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = db_path
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(db_path) and os.unlink(db_path))
        app_module.init_db()
        now = app_module.utcnow()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(99,'Org','org-latch','active',?)", (now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,desired_agent_version,update_status,created_at,organization_id) VALUES('d1','pc1','x','1.0.0-rc.10','1.0.0-rc.11','installed',?,99)", (now,))
            old_release = conn.execute("INSERT INTO agent_releases(version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES('1.0.0-rc.10','stable','10.zip','/tmp/10.zip',?,1,1,?)", ('A' * 64, now)).lastrowid
            next_release = conn.execute("INSERT INTO agent_releases(version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES('1.0.0-rc.11','stable','11.zip','/tmp/11.zip',?,1,1,?)", ('B' * 64, now)).lastrowid
            conn.execute("INSERT INTO agent_deployments(release_id,scope_type,scope_id,organization_id,rollout_percent,active,created_at) VALUES(?,'device','d1',99,100,1,?)", (next_release, now))
            conn.execute("INSERT INTO agent_update_history(device_id,release_id,from_version,target_version,status,created_at) VALUES('d1',?,'1.0.0-rc.9','1.0.0-rc.10','installing',?)", (old_release, now))
            conn.commit()

            app_module.refresh_device_update_target(conn, "d1")
            old_status = conn.execute("SELECT status FROM agent_update_history WHERE device_id='d1' AND release_id=?", (old_release,)).fetchone()[0]
            queued = conn.execute("SELECT COUNT(*) FROM commands WHERE device_id='d1' AND command_type='update_agent' AND status='pending'").fetchone()[0]

        self.assertEqual("completed", old_status)
        self.assertEqual(1, queued)


if __name__ == "__main__":
    unittest.main()
