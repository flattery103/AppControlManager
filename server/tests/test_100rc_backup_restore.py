import os, sqlite3, subprocess, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


class ReleaseCandidateBackupRestoreTests(unittest.TestCase):
    def test_backup_and_restore_preserve_integrity(self):
        with tempfile.TemporaryDirectory(prefix='acm-rc-backup-') as td:
            root=Path(td); db=root/'live.db'; backup=root/'backup.db'; restored=root/'restored.db'
            with sqlite3.connect(db) as conn:
                conn.execute('CREATE TABLE evidence(id INTEGER PRIMARY KEY,value TEXT)')
                conn.execute("INSERT INTO evidence(value) VALUES('preserved')"); conn.commit()
            env={**os.environ,'APPCONTROL_DB':str(db),'APPCONTROL_SKIP_SERVICE':'1'}
            subprocess.run(['bash',str(ROOT/'server/backup-server.sh'),str(backup)],check=True,env=env,capture_output=True,text=True)
            env['APPCONTROL_DB']=str(restored)
            subprocess.run(['bash',str(ROOT/'server/restore-server.sh'),str(backup),'--confirm'],check=True,env=env,capture_output=True,text=True)
            with sqlite3.connect(restored) as conn:
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertEqual(conn.execute('SELECT value FROM evidence').fetchone()[0],'preserved')


if __name__=='__main__': unittest.main()
