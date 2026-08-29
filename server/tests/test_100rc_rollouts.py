import os, sqlite3, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]


class ReleaseCandidateRolloutTests(unittest.TestCase):
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


if __name__=='__main__': unittest.main()
