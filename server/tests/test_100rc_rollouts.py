import os, sqlite3, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]


class ReleaseCandidateRolloutTests(unittest.TestCase):
    def app_with_temp_db(self):
        server=ROOT/'server'; sys.path.insert(0,str(server)) if str(server) not in sys.path else None
        import app
        fd,path=tempfile.mkstemp(prefix='acm-rc-rollout-',suffix='.db'); os.close(fd); os.unlink(path)
        old=app.DB_PATH; app.DB_PATH=path; app.init_db()
        self.addCleanup(setattr,app,'DB_PATH',old)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app,path

    def test_deployment_can_start_paused(self):
        server=ROOT/'server'; sys.path.insert(0,str(server)) if str(server) not in sys.path else None
        import app
        fd,path=tempfile.mkstemp(prefix='acm-rc-rollout-',suffix='.db'); os.close(fd); os.unlink(path)
        old=app.DB_PATH; app.DB_PATH=path; app.init_db()
        try:
            now=app.utcnow()
            with sqlite3.connect(path) as conn:
                conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(801,'One','rollout-one','active',?)",(now,))
                conn.execute("INSERT INTO agent_releases(id,version,channel,file_name,file_path,sha256,size_bytes,active,created_at,created_by) VALUES(9,'1.0.0-rc.1','stable','a.zip','/tmp/a.zip',?,1,1,?,'admin')",('a'*64,now))
                conn.commit()
            app.create_agent_deployment('release:9','organization:801',25,1,app.Principal(1,'admin','Admin','global_admin',None))
            with sqlite3.connect(path) as conn:
                row=conn.execute('SELECT active,status,rollout_percent FROM agent_deployments').fetchone()
            self.assertEqual(row,(0,'paused',25))
        finally:
            app.DB_PATH=old
            if os.path.exists(path): os.unlink(path)

    def test_paused_deployment_can_be_deleted_and_targets_are_recalculated(self):
        app,path=self.app_with_temp_db(); now=app.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(802,'Delete','delete-rollout','active',?)",(now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,desired_agent_version,created_at,organization_id) VALUES('delete-device','DELETE-PC','x','1.0.0-rc.7','1.0.0-rc.7',?,802)",(now,))
            conn.execute("INSERT INTO agent_releases(id,version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES(7,'1.0.0-rc.7','stable','7.zip','/tmp/7.zip',?,1,1,?)",('7'*64,now))
            conn.execute("INSERT INTO agent_releases(id,version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES(9,'1.0.0-rc.9','stable','9.zip','/tmp/9.zip',?,1,1,?)",('9'*64,now))
            conn.execute("INSERT INTO agent_deployments(id,release_id,scope_type,scope_id,organization_id,rollout_percent,active,status,created_at) VALUES(21,7,'device','delete-device',802,100,0,'paused',?)",(now,))
            conn.execute("INSERT INTO agent_deployments(id,channel,scope_type,rollout_percent,active,status,created_at) VALUES(22,'stable','global',100,1,'active',?)",(now,))
            conn.commit()

        response=app.delete_agent_deployment(21,app.Principal(1,'admin','Admin','global_admin',None))

        self.assertEqual(response.status_code,303)
        with sqlite3.connect(path) as conn:
            conn.row_factory=sqlite3.Row
            self.assertIsNone(conn.execute('SELECT id FROM agent_deployments WHERE id=21').fetchone())
            device=conn.execute("SELECT desired_agent_version,update_status FROM devices WHERE id='delete-device'").fetchone()
            command=conn.execute("SELECT status FROM commands WHERE device_id='delete-device' AND command_type='update_agent'").fetchone()
            audit=conn.execute("SELECT action FROM audit_log WHERE object_id='21' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(tuple(device),('1.0.0-rc.9','queued'))
        self.assertEqual(command['status'],'pending')
        self.assertEqual(audit['action'],'agent_deployment_deleted')

    def test_active_deployment_must_be_paused_before_deletion(self):
        app,path=self.app_with_temp_db(); now=app.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO agent_deployments(id,channel,scope_type,rollout_percent,active,status,created_at) VALUES(25,'stable','global',100,1,'active',?)",(now,))
            conn.commit()

        with self.assertRaises(app.HTTPException) as raised:
            app.delete_agent_deployment(25,app.Principal(1,'admin','Admin','global_admin',None))

        self.assertEqual(raised.exception.status_code,409)
        self.assertIn('Pause',raised.exception.detail)
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM agent_deployments WHERE id=25').fetchone()[0],1)

    def test_paused_deployment_page_offers_delete_action(self):
        app,path=self.app_with_temp_db(); now=app.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO agent_deployments(id,channel,scope_type,rollout_percent,active,status,created_at) VALUES(26,'beta','global',100,0,'paused',?)",(now,))
            conn.commit()

        html=app.agent_updates_page(app.Principal(1,'admin','Admin','global_admin',None)).body.decode()

        self.assertIn("/admin/agent-deployments/26/delete",html)
        self.assertIn('>Delete</button>',html)

    def test_completed_manual_device_assignment_retires_and_latest_stable_takes_over(self):
        app,path=self.app_with_temp_db(); now=app.utcnow()
        with sqlite3.connect(path) as conn:
            conn.row_factory=sqlite3.Row
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(803,'Retire','retire-rollout','active',?)",(now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,desired_agent_version,created_at,organization_id) VALUES('retire-device','RETIRE-PC','x','1.0.0-rc.8','1.0.0-rc.8',?,803)",(now,))
            conn.execute("INSERT INTO agent_releases(id,version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES(8,'1.0.0-rc.8','stable','8.zip','/tmp/8.zip',?,1,1,?)",('8'*64,now))
            conn.execute("INSERT INTO agent_releases(id,version,channel,file_name,file_path,sha256,size_bytes,active,created_at) VALUES(9,'1.0.0-rc.9','stable','9.zip','/tmp/9.zip',?,1,1,?)",('9'*64,now))
            conn.execute("INSERT INTO agent_deployments(id,release_id,scope_type,scope_id,organization_id,rollout_percent,active,status,created_at,created_by) VALUES(31,8,'device','retire-device',803,100,1,'active',?,'admin')",(now,))
            conn.execute("INSERT INTO agent_deployments(id,channel,scope_type,rollout_percent,active,status,created_at) VALUES(32,'stable','global',100,1,'active',?)",(now,))
            app.refresh_device_update_target(conn,'retire-device')
            conn.commit()
            manual=conn.execute('SELECT active,status,disabled_by FROM agent_deployments WHERE id=31').fetchone()
            device=conn.execute("SELECT desired_agent_version,update_status FROM devices WHERE id='retire-device'").fetchone()
            command=conn.execute("SELECT status FROM commands WHERE device_id='retire-device' AND command_type='update_agent'").fetchone()

        self.assertEqual(tuple(manual),(0,'completed','system'))
        self.assertEqual(tuple(device),('1.0.0-rc.9','queued'))
        self.assertEqual(command['status'],'pending')


if __name__=='__main__': unittest.main()
