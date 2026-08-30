import os
import sqlite3
import sys
import tempfile
import unittest
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseCandidatePolicyManagementTests(unittest.TestCase):
    def app_with_temp_db(self):
        server_dir = ROOT / "server"
        if str(server_dir) not in sys.path:
            sys.path.insert(0, str(server_dir))
        import app as app_module

        fd, path = tempfile.mkstemp(prefix="acm-100rc-policy-", suffix=".db")
        os.close(fd)
        os.unlink(path)
        old_path = app_module.DB_PATH
        app_module.DB_PATH = path
        app_module.init_db()
        self.addCleanup(setattr, app_module, "DB_PATH", old_path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return app_module, path

    def seed_approval(self, app_module, path, policy_id, components=2):
        now = app_module.utcnow()
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(701,'RC7 Org','rc7-org','active',?)", (now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id) VALUES('rc7-device','RC7-PC','x',?,701)", (now,))
            request_id = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at) VALUES('rc7-device','C:\\Apps\\main.exe','approved',?)", (now,)).lastrowid
            for index in range(components):
                conn.execute(
                    """INSERT INTO approved_components(device_id,request_id,file_path,publisher,product_name,rule_type,policy_id,approved_at,status)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    ('rc7-device', request_id, f'C:\\Apps\\component{index}.dll', 'CN=Vendor', f'Component {index}', 'Background Application Bundle', policy_id, now, 'approved'),
                )
            conn.commit()

    def test_approval_page_groups_bundle_and_accepts_braced_policy_guid(self):
        app_module, path = self.app_with_temp_db()
        self.seed_approval(app_module, path, '{11111111-1111-1111-1111-111111111111}')
        principal = app_module.Principal(1, 'admin', 'Admin', 'global_admin', None)

        response = app_module.approved_page(busy=0, q='', page_num=1, principal=principal)
        html = response.body.decode()

        self.assertEqual(html.count('2 components in policy'), 1)
        self.assertEqual(html.count('Revoke application approval'), 1)
        self.assertEqual(html.count('>Block</button>'), 1)

    def test_block_action_does_not_require_a_removable_policy_guid(self):
        app_module, path = self.app_with_temp_db()
        self.seed_approval(app_module, path, 'legacy-command-id', components=1)
        principal = app_module.Principal(1, 'admin', 'Admin', 'global_admin', None)

        html = app_module.approved_page(busy=0, q='', page_num=1, principal=principal).body.decode()

        self.assertNotIn('Revoke application approval', html)
        self.assertEqual(html.count('>Block</button>'), 1)

    def seed_deletable_allow_policy(self, app_module, path):
        now = app_module.utcnow()
        policy_guid = '{22222222-2222-2222-2222-222222222222}'
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(702,'Delete Org','delete-org','active',?)", (now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,agent_version,created_at,organization_id) VALUES('delete-device','DELETE-PC','x','0.12.0',?,702)", (now,))
            request_id = conn.execute("INSERT INTO approval_requests(device_id,file_path,status,created_at) VALUES('delete-device','C:\\Apps\\delete.exe','approved',?)", (now,)).lastrowid
            policy_id = conn.execute(
                """INSERT INTO scoped_policies(name,action,scope_type,scope_id,organization_id,identity_type,file_path,source_request_id,active,created_at,created_by)
                   VALUES('Delete Me','allow','device','delete-device',702,'path','C:\\Apps\\delete.exe',?,1,?,'admin')""",
                (request_id, now),
            ).lastrowid
            conn.execute(
                """INSERT INTO approved_components(device_id,request_id,file_path,policy_id,approved_at,policy_definition_id,status)
                   VALUES('delete-device',?,'C:\\Apps\\delete.exe',?,?,?,'approved')""",
                (request_id, policy_guid, now, policy_id),
            )
            conn.commit()
        return policy_id

    def test_bulk_delete_queues_cleanup_and_auto_finalizes_after_completion(self):
        app_module, path = self.app_with_temp_db()
        policy_id = self.seed_deletable_allow_policy(app_module, path)
        principal = app_module.Principal(1, 'admin', 'Admin', 'global_admin', None)

        response = app_module.bulk_delete_policies(policy_ids=[policy_id], principal=principal)
        self.assertEqual(response.status_code, 303)

        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            policy = conn.execute('SELECT * FROM scoped_policies WHERE id=?', (policy_id,)).fetchone()
            command = conn.execute("SELECT * FROM commands WHERE command_type='revoke_approval'").fetchone()
            self.assertEqual(policy['active'], 0)
            self.assertIsNotNone(policy['delete_requested_at'])
            self.assertIsNone(policy['deleted_at'])
            self.assertIsNotNone(command)
            conn.execute("UPDATE commands SET status='processing' WHERE id=?", (command['id'],))
            conn.commit()

        app_module.complete_command(
            command['id'],
            app_module.CommandComplete(success=True, result='removed'),
            'delete-device',
        )

        with sqlite3.connect(path) as conn:
            deleted_at = conn.execute('SELECT deleted_at FROM scoped_policies WHERE id=?', (policy_id,)).fetchone()[0]
        self.assertIsNotNone(deleted_at)

    def test_single_delete_redirects_while_cleanup_is_pending(self):
        app_module, path = self.app_with_temp_db()
        policy_id = self.seed_deletable_allow_policy(app_module, path)
        principal = app_module.Principal(1, 'admin', 'Admin', 'global_admin', None)
        with sqlite3.connect(path) as conn:
            conn.execute('UPDATE scoped_policies SET active=0 WHERE id=?', (policy_id,))
            conn.commit()

        response = app_module.delete_policy(policy_id, principal)

        self.assertEqual(response.status_code, 303)
        self.assertIn('delete_requested=1', response.headers['location'])
        with sqlite3.connect(path) as conn:
            queued = conn.execute("SELECT COUNT(*) FROM commands WHERE command_type='revoke_approval' AND status='pending'").fetchone()[0]
        self.assertEqual(queued, 1)

    def test_policy_page_shows_bulk_selection_and_pending_cleanup_progress(self):
        app_module, path = self.app_with_temp_db()
        policy_id = self.seed_deletable_allow_policy(app_module, path)
        principal = app_module.Principal(1, 'admin', 'Admin', 'global_admin', None)
        app_module.delete_policy(policy_id, principal)

        html = app_module.policies_page(
            q='', policy_action='', policy_status='', page_num=1,
            delete_requested=1, principal=principal,
        ).body.decode()

        self.assertIn("action='/admin/policies/delete-selected'", html)
        self.assertIn('Disable and Delete Selected', html)
        self.assertIn('Pending deletion', html)
        self.assertIn('1 endpoint command', html)

    def test_disabling_block_policy_queues_braced_policy_guid_cleanup(self):
        app_module, path = self.app_with_temp_db()
        now = app_module.utcnow()
        principal = app_module.Principal(1, 'admin', 'Admin', 'global_admin', None)
        with sqlite3.connect(path) as conn:
            conn.execute("INSERT INTO organizations(id,name,slug,status,created_at) VALUES(703,'Block Org','block-org','active',?)", (now,))
            conn.execute("INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id) VALUES('block-device','BLOCK-PC','x',?,703)", (now,))
            policy_id = conn.execute(
                """INSERT INTO scoped_policies(name,action,scope_type,scope_id,organization_id,identity_type,file_path,active,created_at,created_by)
                   VALUES('Block Me','block','device','block-device',703,'path','C:\\Apps\\blocked.exe',1,?,'admin')""",
                (now,),
            ).lastrowid
            conn.execute(
                """INSERT INTO blocked_applications(device_id,file_path,status,policy_id,policy_definition_id,created_at)
                   VALUES('block-device','C:\\Apps\\blocked.exe','blocked','{33333333-3333-3333-3333-333333333333}',?,?)""",
                (policy_id, now),
            )
            conn.commit()

        app_module.disable_policy(policy_id, principal)

        with sqlite3.connect(path) as conn:
            command = conn.execute("SELECT command_type,payload FROM commands WHERE command_type='unblock_file'").fetchone()
        self.assertIsNotNone(command)
        self.assertIn('33333333-3333-3333-3333-333333333333', command[1])

    def test_failed_policy_cleanup_can_be_retried_without_recreating_policy(self):
        app_module, path = self.app_with_temp_db()
        policy_id = self.seed_deletable_allow_policy(app_module, path)
        principal = app_module.Principal(1, 'admin', 'Admin', 'global_admin', None)
        app_module.delete_policy(policy_id, principal)
        with sqlite3.connect(path) as conn:
            command_id = conn.execute("SELECT id FROM commands WHERE command_type='revoke_approval'").fetchone()[0]
            conn.execute("UPDATE commands SET status='failed',completed_at=?,result='temporary failure' WHERE id=?", (app_module.utcnow(), command_id))
            conn.commit()

        response = app_module.retry_policy_deletion(policy_id, principal)

        self.assertEqual(response.status_code, 303)
        with sqlite3.connect(path) as conn:
            command = conn.execute('SELECT status,result,completed_at FROM commands WHERE id=?', (command_id,)).fetchone()
            policy = conn.execute('SELECT deleted_at FROM scoped_policies WHERE id=?', (policy_id,)).fetchone()
        self.assertEqual(command, ('pending', None, None))
        self.assertIsNone(policy[0])


if __name__ == '__main__':
    unittest.main()
