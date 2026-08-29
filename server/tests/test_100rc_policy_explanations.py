import os, sqlite3, sys, tempfile, unittest
from pathlib import Path
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]


class ReleaseCandidatePolicyExplanationTests(unittest.TestCase):
    def setup_app(self):
        server_dir=ROOT/'server'
        if str(server_dir) not in sys.path: sys.path.insert(0,str(server_dir))
        import app
        fd,path=tempfile.mkstemp(prefix='acm-rc-explain-',suffix='.db'); os.close(fd); os.unlink(path)
        old=app.DB_PATH; app.DB_PATH=path; app.init_db()
        self.addCleanup(setattr,app,'DB_PATH',old); self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        now=app.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(701,'One','one-explain','active',?)",(now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,learning_mode,policy_mode,created_at,organization_id) VALUES('d1','PC','x',0,'enforcement',?,701)",(now,))
            conn.commit()
        return app,path

    def test_explains_active_manual_approval(self):
        app,path=self.setup_app(); now=app.utcnow(); digest='ab'*32
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO approval_requests(id,device_id,file_path,sha256,status,created_at,decided_by) VALUES(10,'d1','C:/App/app.exe',?,'approved',?,'admin')",(digest,now))
            conn.execute("INSERT INTO approved_applications(device_id,request_id,file_path,sha256,rule_type,policy_id,approved_at,status) VALUES('d1',10,'C:/App/app.exe',?,'Hash','AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE',?,'approved')",(digest,now))
            conn.commit(); conn.row_factory=sqlite3.Row
            result=app.build_policy_explanation(conn,app.Principal(1,'admin','Admin','org_admin',701),device_id='d1',sha256=digest)
        self.assertEqual(result['decision'],'allowed'); self.assertEqual(result['source'],'manual_approval')
        self.assertEqual(result['policy_id'],'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')

    def test_explicit_block_precedes_approval(self):
        app,path=self.setup_app(); now=app.utcnow(); digest='cd'*32
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO approved_applications(device_id,file_path,sha256,rule_type,policy_id,approved_at,status) VALUES('d1','C:/App/app.exe',?,'Hash','ALLOW-ID',?,'approved')",(digest,now))
            conn.execute("INSERT INTO blocked_applications(device_id,file_path,sha256,rule_type,policy_id,status,created_at,blocked_at,blocked_by) VALUES('d1','C:/App/app.exe',?,'Hash','BLOCK-ID','blocked',?,?, 'admin')",(digest,now,now))
            conn.commit(); conn.row_factory=sqlite3.Row
            result=app.build_policy_explanation(conn,app.Principal(1,'admin','Admin','org_admin',701),device_id='d1',sha256=digest)
        self.assertEqual(result['decision'],'blocked'); self.assertEqual(result['source'],'explicit_block')

    def test_cross_tenant_explanation_is_denied(self):
        app,path=self.setup_app()
        with sqlite3.connect(path) as conn:
            conn.row_factory=sqlite3.Row
            with self.assertRaises(HTTPException) as denied:
                app.build_policy_explanation(conn,app.Principal(2,'other','Other','org_admin',999),device_id='d1',file_path='C:/App/app.exe')
        self.assertEqual(denied.exception.status_code,403)


if __name__=='__main__': unittest.main()
