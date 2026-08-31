import os
import json
import sqlite3
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
import app


def temp_db():
    fd, path = tempfile.mkstemp(prefix="acm-rc12-", suffix=".db")
    os.close(fd)
    os.unlink(path)
    previous = app.DB_PATH
    app.DB_PATH = path
    app.init_db()
    return path, previous


def restore_db(path, previous):
    app.DB_PATH = previous
    if os.path.exists(path):
        os.unlink(path)


def seed_org_device(conn, org_id, device_id):
    now = app.utcnow()
    conn.execute(
        "INSERT INTO organizations(id,name,slug,status,created_at) VALUES(?,?,?,?,?)",
        (org_id, f"Org {org_id}", f"org-{org_id}", "active", now),
    )
    conn.execute(
        "INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id) VALUES(?,?,?,?,?)",
        (device_id, device_id, "x", now, org_id),
    )


def test_pending_notification_is_durable_scoped_and_survives_tenant_reassignment():
    path, previous = temp_db()
    try:
        now = app.utcnow()
        with app.db() as conn:
            seed_org_device(conn, 10, "d10")
            seed_org_device(conn, 20, "d20")
            user_id = conn.execute(
                "INSERT INTO users(username,password_hash,role,organization_id,active,created_at) VALUES('approver','x','approver',10,1,?)",
                (now,),
            ).lastrowid
            old_request = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,product_name,status,created_at) VALUES('d20','C:\\Old.exe','Old request','pending',?)",
                (now,),
            ).lastrowid
            current_request = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,product_name,status,created_at) VALUES('d10','C:\\New.exe','New request','pending',?)",
                (now,),
            ).lastrowid

            principal = app.Principal(user_id, "approver", "Approver", "approver", 10)
            notice = app.pending_request_notification(conn, principal)
            assert notice["id"] == current_request
            app.acknowledge_request_notification(conn, principal, current_request, "dismissed")
            assert app.pending_request_notification(conn, principal) is None

            reassigned = app.Principal(user_id, "approver", "Approver", "approver", 20)
            notice = app.pending_request_notification(conn, reassigned)
            assert notice["id"] == old_request
    finally:
        restore_db(path, previous)


def test_notification_considers_only_pending_requests():
    path, previous = temp_db()
    try:
        now = app.utcnow()
        with app.db() as conn:
            seed_org_device(conn, 10, "d10")
            principal = app.Principal(99, "admin", "Admin", "global_admin", None)
            conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,product_name,status,created_at) VALUES('d10','C:\\Done.exe','Completed request','approved',?)",
                (now,),
            )
            pending_id = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,product_name,status,created_at) VALUES('d10','C:\\Pending.exe','Pending request','pending',?)",
                (now,),
            ).lastrowid
            assert app.pending_request_notification(conn, principal)["id"] == pending_id
    finally:
        restore_db(path, previous)


def test_revocation_correlates_direct_loaded_components_without_transitive_expansion():
    path, previous = temp_db()
    try:
        now = app.utcnow()
        publisher = "CN=Google LLC"
        with app.db() as conn:
            seed_org_device(conn, 10, "d10")
            chrome = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,publisher,product_name,status,created_at) VALUES('d10',?,?,?,?,?)",
                (r"C:\Program Files\Google\Chrome\Application\chrome.exe", publisher, "Google Chrome", "approved", now),
            ).lastrowid
            dlls = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,publisher,product_name,status,created_at) VALUES('d10',?,?,?,?,?)",
                (r"C:\Program Files\Google\Chrome\Application\152\helper.dll", publisher, "Google Chrome", "approved", now),
            ).lastrowid
            transitive = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,publisher,product_name,status,created_at) VALUES('d10',?,?,?,?,?)",
                (r"C:\Temp\third.dll", publisher, "Google Chrome", "approved", now),
            ).lastrowid
            conflict = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,publisher,product_name,status,created_at) VALUES('d10',?,?,?,?,?)",
                (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "CN=Unrelated Vendor", "Impostor", "approved", now),
            ).lastrowid
            conn.execute(
                "INSERT INTO approval_request_items(request_id,original_path,parent_path,publisher) VALUES(?,?,?,?)",
                (dlls, r"C:\Program Files\Google\Chrome\Application\152\helper.dll", r"C:\Program Files\Google\Chrome\Application\chrome.exe", publisher),
            )
            conn.execute(
                "INSERT INTO approval_request_items(request_id,original_path,parent_path,publisher) VALUES(?,?,?,?)",
                (transitive, r"C:\Temp\third.dll", r"C:\Program Files\Google\Chrome\Application\152\helper.dll", publisher),
            )
            for index, request_id in enumerate((chrome, dlls, transitive, conflict), start=1):
                request = conn.execute("SELECT * FROM approval_requests WHERE id=?", (request_id,)).fetchone()
                conn.execute(
                    """INSERT INTO approved_components
                       (device_id,request_id,file_path,publisher,product_name,policy_id,approved_at,status)
                       VALUES('d10',?,?,?,?,?,?,'approved')""",
                    (request_id, request['file_path'], request['publisher'], request['product_name'], f"00000000-0000-0000-0000-{index:012d}", now),
                )

            correlated = app.correlated_request_ids_for_revocation(conn, "d10", chrome)

        assert correlated == [chrome, dlls]
        assert transitive not in correlated
        assert conflict not in correlated
    finally:
        restore_db(path, previous)


def test_revocation_queues_every_direct_application_policy_layer():
    path, previous = temp_db()
    try:
        now = app.utcnow()
        publisher = "CN=Google LLC"
        with app.db() as conn:
            seed_org_device(conn, 10, "d10")
            primary = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,publisher,status,created_at) VALUES('d10',?,?, 'approved',?)",
                (r"C:\Apps\Chrome\chrome.exe", publisher, now),
            ).lastrowid
            related = conn.execute(
                "INSERT INTO approval_requests(device_id,file_path,publisher,status,created_at) VALUES('d10',?,?, 'approved',?)",
                (r"C:\Apps\Chrome\152\helper.dll", publisher, now),
            ).lastrowid
            conn.execute(
                "INSERT INTO approval_request_items(request_id,original_path,parent_path,publisher) VALUES(?,?,?,?)",
                (related, r"C:\Apps\Chrome\152\helper.dll", r"C:\Apps\Chrome\chrome.exe", publisher),
            )
            policy_ids = []
            for request_id, suffix in ((primary, 11), (primary, 12), (related, 21), (related, 22)):
                policy_id = f"00000000-0000-0000-0000-{suffix:012d}"
                policy_ids.append(policy_id)
                conn.execute(
                    """INSERT INTO approved_components
                       (device_id,request_id,file_path,publisher,policy_id,approved_at,status)
                       VALUES('d10',?,?,?,?,?,'approved')""",
                    (request_id, r"C:\Apps\Chrome\chrome.exe" if request_id == primary else r"C:\Apps\Chrome\152\helper.dll", publisher, policy_id, now),
                )

            queued = app.queue_linked_policy_revocations(conn, "d10", primary, "admin")
            commands = conn.execute(
                "SELECT payload FROM commands WHERE command_type='revoke_approval' ORDER BY id"
            ).fetchall()
            statuses = conn.execute("SELECT DISTINCT status FROM approved_components").fetchall()

        assert queued == 4
        assert {json.loads(row[0])["policy_id"] for row in commands} == set(policy_ids)
        assert [row[0] for row in statuses] == ['revoking']
    finally:
        restore_db(path, previous)


def test_disabling_broader_scope_approval_cleans_component_application_and_background_only_devices():
    path, previous = temp_db()
    try:
        now = app.utcnow()
        with app.db() as conn:
            seed_org_device(conn, 10, "d10-a")
            conn.execute(
                "INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id) VALUES('d10-b','d10-b','x',?,10)",
                (now,),
            )
            conn.execute(
                "INSERT INTO devices(id,hostname,device_key_hash,created_at,organization_id) VALUES('d10-c','d10-c','x',?,10)",
                (now,),
            )
            scoped_id = conn.execute(
                """INSERT INTO scoped_policies
                   (name,action,scope_type,scope_id,organization_id,identity_type,publisher,product_name,active,created_at)
                   VALUES('Chrome','allow','organization','10',10,'publisher_product','CN=Google LLC','Google Chrome',1,?)""",
                (now,),
            ).lastrowid
            component_ids = []
            for index, device_id in enumerate(("d10-a", "d10-b", "d10-c"), start=1):
                request_id = conn.execute(
                    "INSERT INTO approval_requests(device_id,file_path,publisher,product_name,status,created_at) VALUES(?,?,?,?, 'approved',?)",
                    (device_id, rf"C:\Apps\Chrome{index}\chrome.exe", "CN=Google LLC", "Google Chrome", now),
                ).lastrowid
                values = (device_id, request_id, rf"C:\Apps\Chrome{index}\chrome.exe", "CN=Google LLC", "Google Chrome", f"10000000-0000-0000-0000-{index:012d}", now, scoped_id)
                if device_id == "d10-a":
                    component_ids.append(conn.execute(
                        """INSERT INTO approved_components
                           (device_id,request_id,file_path,publisher,product_name,policy_id,approved_at,policy_definition_id,status)
                           VALUES(?,?,?,?,?,?,?,?, 'approved')""", values,
                    ).lastrowid)
                elif device_id == "d10-b":
                    conn.execute(
                        """INSERT INTO approved_applications
                           (device_id,request_id,file_path,publisher,product_name,policy_id,approved_at,policy_definition_id,status)
                           VALUES(?,?,?,?,?,?,?,?, 'approved')""", values,
                    )
                else:
                    conn.execute(
                        """INSERT INTO approval_background_policies
                           (device_id,request_id,policy_definition_id,policy_id,status,created_at)
                           VALUES(?,?,?,?, 'installed',?)""",
                        (device_id, request_id, scoped_id, values[5], now),
                    )

        principal = app.Principal(1, "admin", "Admin", "global_admin", None)
        app.revoke_approved(component_ids[0], principal)
        with app.db() as conn:
            devices = conn.execute(
                "SELECT DISTINCT device_id FROM commands WHERE command_type='revoke_approval' ORDER BY device_id"
            ).fetchall()
        assert [row[0] for row in devices] == ["d10-a", "d10-b", "d10-c"]
    finally:
        restore_db(path, previous)


def test_rc12_page_wires_global_polling_dashboard_refresh_and_25_item_activity():
    source = (ROOT / "server/app.py").read_text(encoding="utf-8")
    assert "/api/pending-request-notification" in source
    assert "/api/dashboard/pending-requests" in source
    assert "data-live-pending-requests" in source
    assert "setInterval(acmPollPendingRequests" in source
    assert "[:25]" in source
    assert "View all activity" in source
    activity = source[source.index("def device_activity("):source.index("def filtered_rows(")]
    assert "LIMIT 5000" not in activity
    assert "UNION ALL" in activity
