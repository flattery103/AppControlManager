import hashlib
import base64
import hmac
import json
import csv
import io
import ntpath
import os
import re
import secrets
import sqlite3
import zipfile
import shutil
import shlex
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from html import escape
from typing import Optional
from pathlib import Path
from urllib.parse import urlencode, quote
from dataclasses import dataclass

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
import qrcode

from release_management import GitHubReleaseInfo, fetch_latest_release

DB_PATH = os.getenv("APPCONTROL_DB", os.getenv("APPGUARD_DB", "appcontrol-manager.db"))
ENROLLMENT_TOKEN = os.getenv("APPCONTROL_ENROLLMENT_TOKEN", os.getenv("APPGUARD_ENROLLMENT_TOKEN", "CHANGE-ME"))
ADMIN_USER = os.getenv("APPCONTROL_ADMIN_USER", os.getenv("APPGUARD_ADMIN_USER", "admin"))
ADMIN_PASSWORD = os.getenv("APPCONTROL_ADMIN_PASSWORD", os.getenv("APPGUARD_ADMIN_PASSWORD", "ChangeMeNow!"))

app = FastAPI(title="AppControl Manager Server", version="0.15.0")
SESSION_COOKIE = "acm_session"
SESSION_HOURS = int(os.getenv("APPCONTROL_SESSION_HOURS", "12"))
COOKIE_SECURE = os.getenv("APPCONTROL_COOKIE_SECURE", "0").strip().lower() in {"1","true","yes","on"}
RELEASE_DIR = Path(os.getenv("APPCONTROL_RELEASE_DIR", "/opt/appcontrol-manager/releases"))
SELF_UPDATE_MIN_VERSION = "0.10.0"
OFFLINE_ATTENTION_DAYS = max(1, int(os.getenv("APPCONTROL_OFFLINE_ATTENTION_DAYS", "7")))
STALE_DEVICE_DAYS = max(1, int(os.getenv("APPCONTROL_STALE_DEVICE_DAYS", "30")))
GITHUB_REPO = os.getenv("APPCONTROL_GITHUB_REPO", "flattery103/AppControlManager").strip()
GITHUB_API_BASE = os.getenv("APPCONTROL_GITHUB_API_BASE", f"https://api.github.com/repos/{GITHUB_REPO}").strip()
GITHUB_TOKEN = os.getenv("APPCONTROL_GITHUB_TOKEN", "").strip()
SERVER_UPDATE_SCRIPT = Path(os.getenv("APPCONTROL_UPDATE_SCRIPT", "/opt/appcontrol-manager/update-from-github.sh"))
SERVER_UPDATE_LOG = Path(os.getenv("APPCONTROL_UPDATE_LOG", "/var/log/appcontrol-manager-update.log"))
SERVER_UPDATE_UNIT = os.getenv("APPCONTROL_UPDATE_UNIT", "appcontrol-manager-update").strip() or "appcontrol-manager-update"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str):
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    with db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                device_key_hash TEXT NOT NULL,
                os_version TEXT,
                learning_mode INTEGER NOT NULL DEFAULT 0,
                policy_mode TEXT NOT NULL DEFAULT 'unknown',
                script_enforcement_disabled INTEGER,
                agent_version TEXT,
                last_seen TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                role TEXT NOT NULL DEFAULT 'read_only',
                organization_id INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                force_password_change INTEGER NOT NULL DEFAULT 0,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                mfa_secret TEXT,
                last_login TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT
            );
            CREATE TABLE IF NOT EXISTS enrollment_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT,
                token_value TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT,
                last_used_at TEXT
            );
            CREATE TABLE IF NOT EXISTS device_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(organization_id,name)
            );
            CREATE TABLE IF NOT EXISTS scoped_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'allow',
                scope_type TEXT NOT NULL,
                scope_id TEXT,
                organization_id INTEGER,
                identity_type TEXT NOT NULL,
                file_path TEXT,
                sha256 TEXT,
                publisher TEXT,
                product_name TEXT,
                minimum_file_version TEXT,
                rule_type TEXT,
                source_request_id INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT,
                disabled_at TEXT,
                disabled_by TEXT
            );
            CREATE TABLE IF NOT EXISTS web_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                mfa_verified INTEGER NOT NULL DEFAULT 0,
                pending_mfa_secret TEXT,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id);
            CREATE TABLE IF NOT EXISTS agent_releases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT 'stable',
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                notes TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT,
                UNIQUE(version,channel)
            );
            CREATE TABLE IF NOT EXISTS agent_deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_id INTEGER,
                channel TEXT,
                scope_type TEXT NOT NULL,
                scope_id TEXT,
                organization_id INTEGER,
                rollout_percent INTEGER NOT NULL DEFAULT 100,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT,
                disabled_at TEXT,
                disabled_by TEXT
            );
            CREATE TABLE IF NOT EXISTS agent_update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                release_id INTEGER,
                deployment_id INTEGER,
                command_id INTEGER,
                from_version TEXT,
                target_version TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_agent_update_history_device ON agent_update_history(device_id,id);
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                actor TEXT,
                action TEXT NOT NULL,
                organization_id INTEGER,
                device_id TEXT,
                object_type TEXT,
                object_id TEXT,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                record_id INTEGER,
                occurred_at TEXT,
                file_path TEXT,
                parent_path TEXT,
                sha256 TEXT,
                publisher TEXT,
                product_name TEXT,
                file_version TEXT,
                raw_json TEXT,
                received_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT,
                publisher TEXT,
                product_name TEXT,
                file_version TEXT,
                reason TEXT,
                requested_by TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT,
                decision_note TEXT
            );
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                result TEXT
            );
            CREATE TABLE IF NOT EXISTS approved_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                request_id INTEGER,
                file_path TEXT NOT NULL,
                sha256 TEXT,
                publisher TEXT,
                product_name TEXT,
                file_version TEXT,
                rule_type TEXT,
                policy_id TEXT,
                approved_at TEXT NOT NULL,
                UNIQUE(device_id, policy_id)
            );
            CREATE TABLE IF NOT EXISTS approval_request_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                policy_source_path TEXT,
                sha256 TEXT,
                publisher TEXT,
                product_name TEXT,
                file_version TEXT,
                parent_path TEXT,
                record_id INTEGER,
                UNIQUE(request_id, original_path)
            );
            CREATE TABLE IF NOT EXISTS approved_components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                request_id INTEGER,
                file_path TEXT NOT NULL,
                sha256 TEXT,
                publisher TEXT,
                product_name TEXT,
                file_version TEXT,
                rule_type TEXT,
                policy_id TEXT,
                approved_at TEXT NOT NULL,
                UNIQUE(device_id, file_path, policy_id)
            );
            CREATE TABLE IF NOT EXISTS blocked_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                source_component_id INTEGER,
                source_request_id INTEGER,
                file_path TEXT NOT NULL,
                policy_source_path TEXT,
                sha256 TEXT,
                publisher TEXT,
                product_name TEXT,
                file_version TEXT,
                rule_type TEXT,
                policy_id TEXT,
                policy_definition_id INTEGER,
                status TEXT NOT NULL DEFAULT 'blocking',
                created_at TEXT NOT NULL,
                blocked_at TEXT,
                blocked_by TEXT,
                unblocked_at TEXT,
                unblocked_by TEXT,
                note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_device_record
                ON events(device_id,event_id,record_id);
            CREATE INDEX IF NOT EXISTS idx_events_event_device
                ON events(event_id,device_id,id);
            """
        )
        # Migrations from earlier POC builds.
        ensure_column(conn, "enrollment_keys", "token_value", "TEXT")
        ensure_column(conn, "devices", "policy_mode", "TEXT NOT NULL DEFAULT 'unknown'")
        ensure_column(conn, "devices", "script_enforcement_disabled", "INTEGER")
        ensure_column(conn, "devices", "agent_version", "TEXT")
        ensure_column(conn, "devices", "desired_agent_version", "TEXT")
        ensure_column(conn, "devices", "update_status", "TEXT")
        ensure_column(conn, "devices", "update_result", "TEXT")
        ensure_column(conn, "devices", "last_update_at", "TEXT")
        ensure_column(conn, "devices", "offboard_status", "TEXT")
        ensure_column(conn, "devices", "offboard_result", "TEXT")
        ensure_column(conn, "devices", "offboard_requested_at", "TEXT")
        ensure_column(conn, "devices", "offboard_completed_at", "TEXT")
        ensure_column(conn, "agent_releases", "installer_file_name", "TEXT")
        ensure_column(conn, "agent_releases", "installer_file_path", "TEXT")
        ensure_column(conn, "agent_releases", "installer_sha256", "TEXT")
        ensure_column(conn, "agent_releases", "installer_size_bytes", "INTEGER")
        ensure_column(conn, "agent_releases", "deleted_at", "TEXT")
        ensure_column(conn, "agent_releases", "deleted_by", "TEXT")
        ensure_column(conn, "devices", "organization_id", "INTEGER")
        ensure_column(conn, "devices", "group_id", "INTEGER")
        ensure_column(conn, "commands", "started_at", "TEXT")
        ensure_column(conn, "commands", "claim_token_hash", "TEXT")
        ensure_column(conn, "commands", "attempt_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "approval_requests", "decided_by", "TEXT")
        ensure_column(conn, "approval_requests", "requested_by", "TEXT")
        ensure_column(conn, "approval_requests", "policy_source_path", "TEXT")
        ensure_column(conn, "approval_requests", "component_count", "INTEGER NOT NULL DEFAULT 1")
        ensure_column(conn, "approval_requests", "request_kind", "TEXT NOT NULL DEFAULT 'file'")
        ensure_column(conn, "approval_requests", "session_key", "TEXT")
        ensure_column(conn, "approved_components", "status", "TEXT NOT NULL DEFAULT 'approved'")
        ensure_column(conn, "approved_components", "revoked_at", "TEXT")
        ensure_column(conn, "approved_components", "revoked_by", "TEXT")
        ensure_column(conn, "approved_components", "policy_definition_id", "INTEGER")
        ensure_column(conn, "approved_applications", "status", "TEXT NOT NULL DEFAULT 'approved'")
        ensure_column(conn, "approved_applications", "revoked_at", "TEXT")
        ensure_column(conn, "approved_applications", "revoked_by", "TEXT")
        ensure_column(conn, "approved_applications", "policy_definition_id", "INTEGER")
        ensure_column(conn, "blocked_applications", "policy_definition_id", "INTEGER")
        ensure_column(conn, "users", "deleted_at", "TEXT")
        ensure_column(conn, "users", "mfa_recovery_codes", "TEXT")
        ensure_column(conn, "scoped_policies", "deleted_at", "TEXT")
        ensure_column(conn, "scoped_policies", "deleted_by", "TEXT")
        # Earlier releases reserved MFA columns but did not support enrollment. Avoid locking out any
        # account that has an inconsistent legacy flag without an actual TOTP secret.
        conn.execute("UPDATE users SET mfa_enabled=0 WHERE mfa_enabled=1 AND COALESCE(mfa_secret,'')=''")
        seed_management_foundation(conn)
        backfill_approved_applications(conn)
        backfill_approved_components(conn)
        cleanup_failed_block_duplicates(conn)
        repair_transitional_states(conn)



def slugify(value: str) -> str:
    value = re.sub(r'[^a-z0-9]+', '-', (value or '').strip().lower()).strip('-')
    return value or 'organization'


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    rounds = 310_000
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, rounds)
    return f"pbkdf2_sha256${rounds}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def password_verify(password: str, encoded: str) -> bool:
    try:
        scheme, rounds_s, salt_s, digest_s = encoded.split('$', 3)
        if scheme != 'pbkdf2_sha256':
            return False
        salt = base64.urlsafe_b64decode(salt_s.encode())
        expected = base64.urlsafe_b64decode(digest_s.encode())
        actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(rounds_s))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def seed_management_foundation(conn: sqlite3.Connection):
    default_org = conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
    if not default_org:
        cur = conn.execute(
            "INSERT INTO organizations(name,slug,status,created_at) VALUES(?,?,?,?)",
            ('Default Organization', 'default', 'active', utcnow()),
        )
        default_org_id = cur.lastrowid
    else:
        default_org_id = default_org['id']

    conn.execute("UPDATE devices SET organization_id=? WHERE organization_id IS NULL", (default_org_id,))

    admin = conn.execute("SELECT id FROM users WHERE lower(username)=lower(?)", (ADMIN_USER,)).fetchone()
    if not admin:
        conn.execute(
            """INSERT INTO users(username,password_hash,display_name,role,organization_id,active,created_at,created_by)
               VALUES(?,?,?,?,NULL,1,?,?)""",
            (ADMIN_USER, password_hash(ADMIN_PASSWORD), ADMIN_USER, 'global_admin', utcnow(), 'bootstrap'),
        )

    legacy_hash = hash_key(ENROLLMENT_TOKEN)
    if ENROLLMENT_TOKEN and ENROLLMENT_TOKEN != 'CHANGE-ME' and not conn.execute(
        "SELECT id FROM enrollment_keys WHERE token_hash=?", (legacy_hash,)
    ).fetchone():
        conn.execute(
            """INSERT INTO enrollment_keys(organization_id,name,token_hash,token_prefix,token_value,active,created_at,created_by)
               VALUES(?,?,?,?,?,1,?,?)""",
            (default_org_id, 'Legacy server enrollment key', legacy_hash, ENROLLMENT_TOKEN[:8], ENROLLMENT_TOKEN, utcnow(), 'bootstrap'),
        )
    elif ENROLLMENT_TOKEN and ENROLLMENT_TOKEN != 'CHANGE-ME':
        conn.execute(
            "UPDATE enrollment_keys SET token_value=COALESCE(token_value,?) WHERE token_hash=?",
            (ENROLLMENT_TOKEN, legacy_hash),
        )


def audit(conn: sqlite3.Connection, actor: str, action: str, *, organization_id=None, device_id=None,
          object_type=None, object_id=None, detail=None):
    conn.execute(
        """INSERT INTO audit_log(occurred_at,actor,action,organization_id,device_id,object_type,object_id,detail)
           VALUES(?,?,?,?,?,?,?,?)""",
        (utcnow(), actor, action, organization_id, device_id, object_type, str(object_id) if object_id is not None else None, detail),
    )


def _parse_utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)
    except Exception:
        return None


def device_record_can_be_deleted(device: sqlite3.Row) -> tuple[bool,str]:
    if (device['offboard_status'] or '').lower() == 'completed':
        return True, 'Agent offboarding completed.'
    last = _parse_utc(device['last_seen']) or _parse_utc(device['created_at'])
    if not last:
        return False, f'Device must be offline for at least {STALE_DEVICE_DAYS} days before its record can be deleted.'
    age = datetime.now(timezone.utc) - last
    if age < timedelta(days=STALE_DEVICE_DAYS):
        remaining = max(1, STALE_DEVICE_DAYS - age.days)
        return False, f'Device was seen too recently. Wait about {remaining} more day(s), or uninstall/offboard it first.'
    return True, f'Device has not checked in for at least {STALE_DEVICE_DAYS} days.'


def purge_device_record(conn: sqlite3.Connection, device_id: str):
    request_ids=[r['id'] for r in conn.execute('SELECT id FROM approval_requests WHERE device_id=?',(device_id,)).fetchall()]
    if request_ids:
        placeholders=','.join('?' for _ in request_ids)
        conn.execute(f'DELETE FROM approval_request_items WHERE request_id IN ({placeholders})',request_ids)
    conn.execute('DELETE FROM approved_components WHERE device_id=?',(device_id,))
    conn.execute('DELETE FROM approved_applications WHERE device_id=?',(device_id,))
    conn.execute('DELETE FROM blocked_applications WHERE device_id=?',(device_id,))
    conn.execute('DELETE FROM approval_requests WHERE device_id=?',(device_id,))
    conn.execute('DELETE FROM events WHERE device_id=?',(device_id,))
    conn.execute('DELETE FROM commands WHERE device_id=?',(device_id,))
    conn.execute('DELETE FROM agent_update_history WHERE device_id=?',(device_id,))
    conn.execute("DELETE FROM agent_deployments WHERE scope_type='device' AND scope_id=?",(device_id,))
    conn.execute("UPDATE scoped_policies SET active=0,deleted_at=COALESCE(deleted_at,?),deleted_by=COALESCE(deleted_by,'device cleanup') WHERE scope_type='device' AND scope_id=?",(utcnow(),device_id))
    conn.execute('DELETE FROM devices WHERE id=?',(device_id,))


@dataclass
class Principal:
    id: int
    username: str
    display_name: str
    role: str
    organization_id: Optional[int]
    force_password_change: bool = False

    @property
    def can_manage_global(self) -> bool:
        return self.role == 'global_admin'

    @property
    def can_manage_org(self) -> bool:
        return self.role in {'global_admin', 'org_admin'}

    @property
    def can_approve(self) -> bool:
        return self.role in {'global_admin', 'org_admin', 'approver'}


def principal_can_see_org(principal: Principal, organization_id: Optional[int]) -> bool:
    return principal.role == 'global_admin' or (organization_id is not None and principal.organization_id == organization_id)


def require_org_access(principal: Principal, organization_id: Optional[int]):
    if not principal_can_see_org(principal, organization_id):
        raise HTTPException(status_code=403, detail='You do not have access to this organization.')


def require_approver(principal: Principal):
    if not principal.can_approve:
        raise HTTPException(status_code=403, detail='Approver permission required.')


def require_org_admin(principal: Principal):
    if not principal.can_manage_org:
        raise HTTPException(status_code=403, detail='Organization administrator permission required.')


def visible_device_clause(principal: Principal, alias: str = 'd'):
    if principal.role == 'global_admin':
        return '1=1', []
    return f'{alias}.organization_id=?', [principal.organization_id]


def policy_scope_label(conn: sqlite3.Connection, row: sqlite3.Row) -> str:
    st = row['scope_type']
    sid = row['scope_id']
    if st == 'global':
        return 'Global'
    if st == 'organization':
        org = conn.execute('SELECT name FROM organizations WHERE id=?', (sid,)).fetchone()
        return f"Organization: {org['name'] if org else sid}"
    if st == 'group':
        grp = conn.execute('SELECT name FROM device_groups WHERE id=?', (sid,)).fetchone()
        return f"Group: {grp['name'] if grp else sid}"
    if st == 'device':
        dev = conn.execute('SELECT hostname FROM devices WHERE id=?', (sid,)).fetchone()
        return f"Device: {dev['hostname'] if dev else sid}"
    return st.title()


def device_matches_policy_scope(conn: sqlite3.Connection, device_id: str, policy: sqlite3.Row) -> bool:
    d = conn.execute('SELECT organization_id,group_id FROM devices WHERE id=?', (device_id,)).fetchone()
    if not d:
        return False
    st, sid = policy['scope_type'], policy['scope_id']
    if st == 'global':
        return True
    if st == 'organization':
        return str(d['organization_id']) == str(sid)
    if st == 'group':
        return d['group_id'] is not None and str(d['group_id']) == str(sid)
    if st == 'device':
        return str(device_id) == str(sid)
    return False


def objv(obj, name, default=None):
    try:
        if isinstance(obj, sqlite3.Row):
            return obj[name] if name in obj.keys() else default
        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)
    except Exception:
        return default


def policy_identity_matches(policy: sqlite3.Row, req) -> bool:
    identity = policy['identity_type']
    if identity == 'publisher_product':
        return bool(objv(req, 'publisher') and objv(req, 'product_name') and policy['publisher'] and policy['product_name']
                    and objv(req, 'publisher') == policy['publisher'] and objv(req, 'product_name') == policy['product_name'])
    if identity == 'publisher_path':
        return bool(objv(req, 'publisher') and policy['publisher'] and objv(req, 'publisher') == policy['publisher']
                    and objv(req, 'file_path') and policy['file_path'] and objv(req, 'file_path').lower() == policy['file_path'].lower())
    if identity == 'sha256':
        return bool(objv(req, 'sha256') and policy['sha256'] and objv(req, 'sha256').lower() == policy['sha256'].lower())
    if identity == 'path':
        return bool(objv(req, 'file_path') and policy['file_path'] and objv(req, 'file_path').lower() == policy['file_path'].lower())
    return False


def find_scoped_policy(conn: sqlite3.Connection, device_id: str, req, action: str):
    rows = conn.execute(
        "SELECT * FROM scoped_policies WHERE active=1 AND action=? ORDER BY CASE scope_type WHEN 'device' THEN 0 WHEN 'group' THEN 1 WHEN 'organization' THEN 2 ELSE 3 END,id DESC",
        (action,),
    ).fetchall()
    for row in rows:
        if device_matches_policy_scope(conn, device_id, row) and policy_identity_matches(row, req):
            return row
    return None


def choose_identity(req) -> str:
    generic_products = {'.net', 'microsoft windows', 'windows', ''}
    if objv(req, 'publisher') and objv(req, 'product_name') and objv(req, 'product_name').strip().lower() not in generic_products:
        return 'publisher_product'
    if objv(req, 'publisher') and objv(req, 'file_path'):
        return 'publisher_path'
    if objv(req, 'sha256'):
        return 'sha256'
    return 'path'


def create_scoped_policy(conn: sqlite3.Connection, request_row, principal: Principal,
                         scope_type: str, scope_id: Optional[str], action: str = 'allow',
                         source_request_id_marker='__auto__') -> int:
    device_id = objv(request_row, 'device_id')
    d = conn.execute('SELECT * FROM devices WHERE id=?', (device_id,)).fetchone()
    if not d:
        raise HTTPException(status_code=404, detail='Device not found')
    require_org_access(principal, d['organization_id'])
    scope_type = (scope_type or 'device').lower()
    action = (action or 'allow').lower()
    if action not in {'allow','block'}:
        raise HTTPException(status_code=400, detail='Invalid policy action')
    if scope_type not in {'device','group','organization','global'}:
        raise HTTPException(status_code=400, detail='Invalid policy scope')
    if scope_type == 'global':
        if not principal.can_manage_global:
            raise HTTPException(status_code=403, detail='Only a global administrator can create global policies.')
        scope_id = None
        org_id = None
    elif scope_type == 'organization':
        scope_id = str(d['organization_id'])
        org_id = d['organization_id']
    elif scope_type == 'group':
        if not d['group_id']:
            raise HTTPException(status_code=400, detail='This device is not assigned to a device group.')
        scope_id = str(d['group_id'])
        org_id = d['organization_id']
    else:
        scope_id = d['id']
        org_id = d['organization_id']

    identity = choose_identity(request_row)
    file_path = objv(request_row, 'file_path') or objv(request_row, 'original_path')
    sha256 = objv(request_row, 'sha256')
    publisher = objv(request_row, 'publisher')
    product_name = objv(request_row, 'product_name')
    file_version = objv(request_row, 'file_version')
    name = product_name or os.path.basename(file_path or '') or 'Application policy'
    source_request_id = objv(request_row, 'id') if source_request_id_marker == '__auto__' else source_request_id_marker

    candidates = conn.execute(
        "SELECT * FROM scoped_policies WHERE active=1 AND action=? AND scope_type=?",
        (action, scope_type),
    ).fetchall()
    probe = {'file_path': file_path, 'sha256': sha256, 'publisher': publisher, 'product_name': product_name, 'file_version': file_version}
    for existing in candidates:
        if str(existing['scope_id'] or '') == str(scope_id or '') and policy_identity_matches(existing, probe):
            return existing['id']

    cur = conn.execute(
        """INSERT INTO scoped_policies(name,action,scope_type,scope_id,organization_id,identity_type,file_path,sha256,publisher,product_name,
                   minimum_file_version,rule_type,source_request_id,active,created_at,created_by)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
        (name, action, scope_type, scope_id, org_id, identity, file_path, sha256, publisher,
         product_name, file_version, 'FilePublisher Application Bundle' if publisher else 'Hash',
         source_request_id, utcnow(), principal.username),
    )
    policy_id = cur.lastrowid
    audit(conn, principal.username, f'policy_{action}_created', organization_id=org_id, device_id=device_id,
          object_type='scoped_policy', object_id=policy_id, detail=f'{scope_type} policy for {name}')
    return policy_id


def queue_scoped_auto_approval(conn: sqlite3.Connection, device_id: str, req, policy: sqlite3.Row,
                               requested_by: Optional[str]) -> Optional[int]:
    existing = find_existing_approved(conn, device_id, req)
    if existing:
        return existing['request_id']
    active = find_active_overlapping_request(conn, device_id, requested_by, [ApprovalComponentIn(
        file_path=objv(req, 'file_path'), policy_source_path=objv(req, 'policy_source_path'), sha256=objv(req, 'sha256'),
        publisher=objv(req, 'publisher'), product_name=objv(req, 'product_name'), file_version=objv(req, 'file_version')
    )])
    if active:
        return active['id']
    if active_device_command(conn, device_id):
        return None
    cur = conn.execute(
        """INSERT INTO approval_requests(device_id,file_path,policy_source_path,sha256,publisher,product_name,file_version,reason,requested_by,
                   status,created_at,component_count,request_kind,decided_at,decided_by,decision_note)
           VALUES(?,?,?,?,?,?,?,?,?,'approving',?,1,'file',?,?,?)""",
        (device_id, objv(req, 'file_path'), objv(req, 'policy_source_path'), objv(req, 'sha256'), objv(req, 'publisher'), objv(req, 'product_name'), objv(req, 'file_version'),
         f"Automatically approved by scoped policy #{policy['id']}", requested_by, utcnow(), utcnow(), 'policy-engine',
         f"Matched {policy['scope_type']} allow policy #{policy['id']}"),
    )
    request_id = cur.lastrowid
    conn.execute(
        """INSERT OR IGNORE INTO approval_request_items(request_id,original_path,policy_source_path,sha256,publisher,product_name,file_version)
           VALUES(?,?,?,?,?,?,?)""",
        (request_id, objv(req, 'file_path'), objv(req, 'policy_source_path'), objv(req, 'sha256'), objv(req, 'publisher'), objv(req, 'product_name'), objv(req, 'file_version')),
    )
    conn.execute(
        "INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",
        (device_id, 'approve_file', json.dumps({'request_id': request_id, 'file_path': objv(req, 'file_path'),
         'policy_source_path': objv(req, 'policy_source_path'), 'scoped_policy_id': policy['id']}), 'pending', utcnow()),
    )
    audit(conn, 'policy-engine', 'scoped_policy_auto_approval', organization_id=policy['organization_id'], device_id=device_id,
          object_type='scoped_policy', object_id=policy['id'], detail=objv(req, 'file_path'))
    return request_id



ALLOWED_AGENT_COMMANDS = {
    'approve_file','approve_session','revoke_approval','block_file','unblock_file',
    'update_agent','uninstall_agent','return_to_learning','enable_enforcement'
}


def validate_agent_command(command_type: str, payload_text: str) -> Optional[str]:
    if command_type not in ALLOWED_AGENT_COMMANDS:
        return f'Unsupported command type: {command_type}'
    try:
        payload = json.loads(payload_text or '{}')
    except Exception:
        return 'Command payload is not valid JSON.'
    if not isinstance(payload, dict):
        return 'Command payload must be a JSON object.'
    def text(name, max_len=4096):
        value=payload.get(name)
        return isinstance(value,str) and 0 < len(value.strip()) <= max_len
    def positive_int(name):
        try: return int(payload.get(name) or 0) > 0
        except Exception: return False
    if command_type == 'approve_file':
        if not positive_int('request_id') or not text('file_path'): return 'approve_file requires a positive request_id and file_path.'
    elif command_type == 'approve_session':
        if not positive_int('request_id'): return 'approve_session requires a positive request_id.'
        components=payload.get('components')
        if not isinstance(components,list) or not components or len(components)>5000: return 'approve_session requires 1-5000 components.'
        for component in components:
            if not isinstance(component,dict) or not isinstance(component.get('file_path'),str) or not component.get('file_path','').strip():
                return 'approve_session contains a component without a file_path.'
    elif command_type == 'revoke_approval':
        if not text('policy_id',256): return 'revoke_approval requires policy_id.'
    elif command_type == 'block_file':
        if not positive_int('block_id') or not text('file_path'): return 'block_file requires a positive block_id and file_path.'
    elif command_type == 'unblock_file':
        if not positive_int('block_id') or not text('policy_id',256): return 'unblock_file requires block_id and policy_id.'
    elif command_type == 'update_agent':
        if not text('target_version',128) or not text('download_path',1024): return 'update_agent requires target_version and download_path.'
        sha=(payload.get('sha256') or '').strip()
        if not re.fullmatch(r'[0-9a-fA-F]{64}',sha): return 'update_agent requires a 64-character SHA256.'
        if not str(payload.get('download_path','')).startswith('/api/agent/releases/'): return 'update_agent download_path is not an AppControl Manager release path.'
    return None


def fail_invalid_command(conn: sqlite3.Connection, row: sqlite3.Row, reason: str):
    result='Rejected by server command validation: ' + reason
    conn.execute("UPDATE commands SET status='failed',completed_at=?,result=?,claim_token_hash=NULL WHERE id=?",(utcnow(),result,row['id']))
    try: payload=json.loads(row['payload'] or '{}')
    except Exception: payload={}
    if row['command_type'] in {'approve_file','approve_session'}:
        request_id=int(payload.get('request_id') or 0)
        if request_id:
            conn.execute("UPDATE approval_requests SET status='approval_failed',decision_note=? WHERE id=? AND status='approving'",(result,request_id))
    d=conn.execute('SELECT organization_id FROM devices WHERE id=?',(row['device_id'],)).fetchone()
    audit(conn,'server','command_validation_failed',organization_id=d['organization_id'] if d else None,device_id=row['device_id'],object_type='command',object_id=row['id'],detail=result)


def requeue_stale_commands(conn: sqlite3.Connection, minutes: int = 10):
    """Return abandoned processing commands to pending after an agent crash/restart."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = conn.execute("SELECT id,started_at FROM commands WHERE status='processing'").fetchall()
    for row in rows:
        try:
            started = datetime.fromisoformat(row["started_at"]) if row["started_at"] else None
        except Exception:
            started = None
        if started is None or started < cutoff:
            conn.execute("UPDATE commands SET status='pending',started_at=NULL,claim_token_hash=NULL WHERE id=?", (row["id"],))


def repair_transitional_states(conn: sqlite3.Connection):
    """Repair UI transition states left behind by an interrupted older agent/server build."""
    requeue_stale_commands(conn)
    for r in conn.execute("SELECT id FROM approval_requests WHERE status='approving'").fetchall():
        token = f'%"request_id": {r["id"]}%'
        cmd = conn.execute(
            "SELECT status,result FROM commands WHERE command_type IN ('approve_file','approve_session') AND payload LIKE ? ORDER BY id DESC LIMIT 1",
            (token,),
        ).fetchone()
        if not cmd:
            conn.execute("UPDATE approval_requests SET status='pending',decision_note='Recovered from an incomplete approval transition.' WHERE id=?", (r["id"],))
        elif cmd["status"] == 'failed':
            conn.execute("UPDATE approval_requests SET status='approval_failed',decision_note=? WHERE id=?", (cmd["result"] or 'Approval command failed.', r["id"]))

    for table in ('approved_components','approved_applications'):
        rows = conn.execute(f"SELECT id,device_id,policy_id FROM {table} WHERE status='revoking'").fetchall()
        for row in rows:
            cmd = conn.execute(
                "SELECT status,result FROM commands WHERE device_id=? AND command_type='revoke_approval' AND payload LIKE ? ORDER BY id DESC LIMIT 1",
                (row["device_id"], f'%{row["policy_id"]}%'),
            ).fetchone()
            if not cmd:
                conn.execute(f"UPDATE {table} SET status='approved' WHERE id=?", (row["id"],))
            elif cmd["status"] == 'failed':
                conn.execute(f"UPDATE {table} SET status='approved' WHERE id=?", (row["id"],))


def active_device_command(conn: sqlite3.Connection, device_id: str):
    return conn.execute(
        "SELECT id,command_type,status,created_at,started_at,payload FROM commands WHERE device_id=? AND status IN ('pending','processing') ORDER BY id LIMIT 1",
        (device_id,),
    ).fetchone()


def cancel_pending_agent_updates(conn: sqlite3.Connection, *, release_id=None, deployment_id=None, reason: str):
    rows=conn.execute("SELECT id,device_id,payload FROM commands WHERE command_type='update_agent' AND status='pending'").fetchall()
    canceled=[]
    for row in rows:
        try: payload=json.loads(row['payload'] or '{}')
        except Exception: payload={}
        if release_id is not None and int(payload.get('release_id') or 0) != int(release_id): continue
        if deployment_id is not None and int(payload.get('deployment_id') or 0) != int(deployment_id): continue
        conn.execute("UPDATE commands SET status='canceled',completed_at=?,result=? WHERE id=? AND status='pending'",(utcnow(),reason,row['id']))
        conn.execute("UPDATE agent_update_history SET status='canceled',detail=?,completed_at=? WHERE command_id=? AND status='queued'",(reason,utcnow(),row['id']))
        conn.execute("UPDATE devices SET update_status='canceled',update_result=? WHERE id=?",(reason,row['device_id']))
        canceled.append(row['device_id'])
    return canceled

def cleanup_failed_block_duplicates(conn: sqlite3.Connection):
    # Older builds created a new failed block row every time the administrator retried.
    # Keep only the newest failed attempt for each device/application; command history remains intact.
    conn.execute(
        """DELETE FROM blocked_applications
           WHERE status='failed' AND id NOT IN (
               SELECT MAX(id) FROM blocked_applications
               WHERE status='failed'
               GROUP BY device_id, CASE WHEN sha256 IS NOT NULL AND sha256 <> '' THEN sha256 ELSE lower(file_path) END
           )"""
    )


def backfill_approved_applications(conn: sqlite3.Connection):
    rows = conn.execute(
        "SELECT id AS command_id,device_id,payload,result,completed_at FROM commands WHERE command_type='approve_file' AND status='completed' ORDER BY id DESC"
    ).fetchall()
    seen = set()
    for row in rows:
        try:
            payload = json.loads(row["payload"] or "{}")
        except Exception:
            payload = {}
        request_id = payload.get("request_id")
        ar = conn.execute("SELECT * FROM approval_requests WHERE id=?", (request_id,)).fetchone() if request_id else None
        path = (ar["file_path"] if ar else None) or payload.get("file_path")
        if not path:
            continue
        dedupe_key = (row["device_id"], path.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        match = re.search(r"Supplemental policy\s+([0-9A-Fa-f-]{36})", row["result"] or "")
        policy_id = match.group(1).upper() if match else f"legacy-command-{row['command_id']}"
        conn.execute(
            """INSERT OR IGNORE INTO approved_applications
               (device_id,request_id,file_path,sha256,publisher,product_name,file_version,rule_type,policy_id,approved_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                row["device_id"], request_id, path,
                ar["sha256"] if ar else None, ar["publisher"] if ar else None,
                ar["product_name"] if ar else None, ar["file_version"] if ar else None,
                "Generated policy (legacy)", policy_id, row["completed_at"] or utcnow(),
            ),
        )


def backfill_approved_components(conn: sqlite3.Connection):
    rows = conn.execute("SELECT * FROM approved_applications ORDER BY id").fetchall()
    for row in rows:
        conn.execute(
            """INSERT OR IGNORE INTO approved_components
               (device_id,request_id,file_path,sha256,publisher,product_name,file_version,rule_type,policy_id,approved_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (row["device_id"], row["request_id"], row["file_path"], row["sha256"], row["publisher"],
             row["product_name"], row["file_version"], row["rule_type"], row["policy_id"], row["approved_at"]),
        )




def version_key(value: str):
    parts=[]
    for token in re.split(r'[.\-+]', (value or '').strip().lower()):
        if token.isdigit(): parts.append((0,int(token)))
        else: parts.append((1,token))
    return tuple(parts)


def version_at_least(current: Optional[str], minimum: str) -> bool:
    if not current:
        return False
    try:
        return version_key(current) >= version_key(minimum)
    except Exception:
        return False


def server_update_asset_names(version: str) -> dict[str, str]:
    version = str(version or '').strip()
    return {
        'source': f'AppControlManager-{version}-source.zip',
        'source_sha256': f'AppControlManager-{version}-source.zip.sha256',
        'agent': f'AppControlManager-Agent-{version}-win-x64.zip',
        'agent_sha256': f'AppControlManager-Agent-{version}-win-x64.zip.sha256',
        'installer': f'AppControlManager-Installer-{version}.exe',
        'installer_sha256': f'AppControlManager-Installer-{version}.exe.sha256',
    }


def server_update_asset_status(info: GitHubReleaseInfo) -> dict[str, bool]:
    return {key: name in info.assets for key, name in server_update_asset_names(info.version).items()}


def _server_update_unit_active() -> bool:
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', '--quiet', f'{SERVER_UPDATE_UNIT}.service'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _server_update_log_tail(max_chars: int = 12000) -> str:
    try:
        if not SERVER_UPDATE_LOG.is_file():
            return ''
        return SERVER_UPDATE_LOG.read_text(encoding='utf-8', errors='replace')[-max_chars:]
    except OSError as exc:
        return f'Unable to read update log: {exc}'


def _launch_server_update() -> str:
    if _server_update_unit_active():
        raise RuntimeError('A server update is already running.')
    if not SERVER_UPDATE_SCRIPT.is_file():
        raise RuntimeError(f'Server updater is not installed at {SERVER_UPDATE_SCRIPT}.')
    try:
        SERVER_UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with SERVER_UPDATE_LOG.open('a', encoding='utf-8') as handle:
            handle.write(f"\n==== AppControl Manager update requested {utcnow()} ====\n")
    except OSError as exc:
        raise RuntimeError(f'Unable to prepare server update log: {exc}') from exc
    command = (
        f"exec {shlex.quote(str(SERVER_UPDATE_SCRIPT))} --install "
        f">> {shlex.quote(str(SERVER_UPDATE_LOG))} 2>&1"
    )
    try:
        result = subprocess.run(
            [
                'systemd-run', f'--unit={SERVER_UPDATE_UNIT}', '--collect', '--property=Type=oneshot',
                '/bin/bash', '-lc', command,
            ],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f'Unable to launch server updater: {exc}') from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise RuntimeError(f'Unable to launch server updater: {detail or "systemd-run failed"}')
    return (result.stdout or '').strip()


def release_for_deployment(conn: sqlite3.Connection, deployment: sqlite3.Row):
    if deployment['release_id']:
        return conn.execute("SELECT * FROM agent_releases WHERE id=? AND active=1 AND deleted_at IS NULL", (deployment['release_id'],)).fetchone()
    channel=(deployment['channel'] or 'stable').lower()
    rows=conn.execute("SELECT * FROM agent_releases WHERE active=1 AND deleted_at IS NULL AND channel=?",(channel,)).fetchall()
    return max(rows,key=lambda r: version_key(r['version'])) if rows else None


def deployment_applies_to_device(deployment: sqlite3.Row, device: sqlite3.Row) -> bool:
    st=deployment['scope_type']; sid=str(deployment['scope_id'] or '')
    if st=='global': return True
    if st=='organization': return str(device['organization_id'] or '')==sid
    if st=='group': return str(device['group_id'] or '')==sid
    if st=='device': return str(device['id'])==sid
    return False


def deployment_rollout_includes(deployment_id: int, release_id: int, device_id: str, percent: int) -> bool:
    percent=max(1,min(int(percent or 100),100))
    if percent>=100: return True
    seed=f"{deployment_id}:{release_id}:{device_id}".encode('utf-8')
    bucket=int(hashlib.sha256(seed).hexdigest()[:8],16)%100
    return bucket < percent


def desired_release_for_device(conn: sqlite3.Connection, device: sqlite3.Row):
    rows=conn.execute("SELECT * FROM agent_deployments WHERE active=1 ORDER BY id DESC").fetchall()
    candidates=[]
    rank={'device':0,'group':1,'organization':2,'global':3}
    for dep in rows:
        if not deployment_applies_to_device(dep,device): continue
        release=release_for_deployment(conn,dep)
        if not release: continue
        if not deployment_rollout_includes(dep['id'],release['id'],device['id'],dep['rollout_percent']): continue
        candidates.append((rank.get(dep['scope_type'],9),-dep['id'],dep,release))
    if not candidates: return None,None
    candidates.sort(key=lambda x:(x[0],x[1]))
    return candidates[0][2],candidates[0][3]


def refresh_device_update_target(conn: sqlite3.Connection, device_id: str):
    device=conn.execute("SELECT * FROM devices WHERE id=?",(device_id,)).fetchone()
    if not device: return
    if (device['offboard_status'] or '').lower() in {'queued','uninstalling','completed'}:
        conn.execute('UPDATE devices SET desired_agent_version=NULL WHERE id=?',(device_id,))
        return
    deployment,release=desired_release_for_device(conn,device)
    if not release:
        conn.execute("UPDATE devices SET desired_agent_version=NULL WHERE id=?",(device_id,))
        return
    desired=release['version']; current=device['agent_version'] or ''; previous_desired=device['desired_agent_version']
    if current==desired:
        conn.execute("UPDATE devices SET desired_agent_version=?,update_status='current',update_result=NULL,last_update_at=COALESCE(last_update_at,?) WHERE id=?",(desired,utcnow(),device_id))
        conn.execute("UPDATE agent_update_history SET status='completed',completed_at=?,detail=COALESCE(detail,'Agent reported target version.') WHERE device_id=? AND target_version=? AND status IN ('queued','installing')",(utcnow(),device_id,desired))
        return
    conn.execute("UPDATE devices SET desired_agent_version=? WHERE id=?",(desired,device_id))
    # Channel tracking should never silently downgrade a device merely because a newer release was
    # disabled or moved between channels. A pinned/device deployment can still intentionally target
    # an older version when an administrator wants to perform a rollback.
    if deployment is not None and deployment['channel'] and current and version_at_least(current,desired) and current != desired:
        conn.execute("UPDATE devices SET update_status='current',update_result=? WHERE id=?",(f"Agent {current} is newer than latest active {deployment['channel']} release {desired}; no downgrade queued.",device_id))
        return
    if previous_desired==desired and (device['update_status'] or '').lower() in {'failed','rolled_back'}:
        return
    if not version_at_least(current,SELF_UPDATE_MIN_VERSION):
        conn.execute("UPDATE devices SET update_status='bootstrap_required',update_result=? WHERE id=?",(f'Manually install {SELF_UPDATE_MIN_VERSION} or later once to enable managed self-update.',device_id))
        return
    active=active_device_command(conn,device_id)
    if active:
        # A newer deployment can supersede an update command that has not started yet. Never cancel a
        # processing command; it may already have downloaded/pre-authorized replacement binaries.
        if active['command_type']=='update_agent' and active['status']=='pending':
            try: active_payload=json.loads(active['payload'] or '{}')
            except Exception: active_payload={}
            if int(active_payload.get('release_id') or 0) != int(release['id']):
                reason=f"Superseded by desired agent release {desired}."
                conn.execute("UPDATE commands SET status='canceled',completed_at=?,result=? WHERE id=? AND status='pending'",(utcnow(),reason,active['id']))
                conn.execute("UPDATE agent_update_history SET status='canceled',detail=?,completed_at=? WHERE command_id=? AND status='queued'",(reason,utcnow(),active['id']))
            else:
                return
        else:
            return
    pattern=f'%"release_id": {release["id"]}%'
    existing=conn.execute("SELECT id,status FROM commands WHERE device_id=? AND command_type='update_agent' AND payload LIKE ? AND status IN ('pending','processing') ORDER BY id DESC LIMIT 1",(device_id,pattern)).fetchone()
    if existing: return
    payload=json.dumps({'release_id':release['id'],'target_version':desired,'sha256':release['sha256'],'download_path':f'/api/agent/releases/{release["id"]}/download','deployment_id':deployment['id'] if deployment else None})
    cur=conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",(device_id,'update_agent',payload,'pending',utcnow()))
    conn.execute("INSERT INTO agent_update_history(device_id,release_id,deployment_id,command_id,from_version,target_version,status,created_at) VALUES(?,?,?,?,?,?,?,?)",(device_id,release['id'],deployment['id'] if deployment else None,cur.lastrowid,current,desired,'queued',utcnow()))
    conn.execute("UPDATE devices SET update_status='queued',update_result=? WHERE id=?",(f'Agent {desired} queued for installation.',device_id))


def refresh_all_device_update_targets(conn: sqlite3.Connection):
    for row in conn.execute("SELECT id FROM devices").fetchall():
        refresh_device_update_target(conn,row['id'])


def validate_agent_package(path: Path, expected_version: str):
    try:
        with zipfile.ZipFile(path,'r') as z:
            names=set(z.namelist())
            manifest_name=next((n for n in names if n.replace('\\','/').lower().endswith('agent-manifest.json')),None)
            if not manifest_name: raise ValueError('agent-manifest.json is missing from the package.')
            manifest=json.loads(z.read(manifest_name).decode('utf-8-sig'))
            if str(manifest.get('version') or '') != expected_version:
                raise ValueError(f"Package manifest version {manifest.get('version')} does not match {expected_version}.")
            normalized={n.replace('\\','/').lower() for n in names}
            required={'service/appcontrolmanager.service.exe','tray/appcontrolmanager.tray.exe','scripts/apply-agentupdate.ps1'}
            missing=[r for r in required if r not in normalized]
            if missing: raise ValueError('Package is missing: '+', '.join(missing))
            return manifest
    except zipfile.BadZipFile as exc:
        raise ValueError('Uploaded file is not a valid ZIP package.') from exc


@app.on_event("startup")
def startup():
    init_db()


class EnrollRequest(BaseModel):
    hostname: str
    os_version: Optional[str] = None
    enrollment_token: str


class EnrollResponse(BaseModel):
    device_id: str
    device_key: str


class HeartbeatRequest(BaseModel):
    learning_mode: Optional[bool] = None
    policy_mode: Optional[str] = None
    script_enforcement_disabled: Optional[bool] = None
    agent_version: Optional[str] = None
    os_version: Optional[str] = None
    update_status: Optional[str] = None
    update_result: Optional[str] = None


class EventIn(BaseModel):
    event_id: int
    record_id: Optional[int] = None
    occurred_at: Optional[str] = None
    file_path: Optional[str] = None
    parent_path: Optional[str] = None
    sha256: Optional[str] = None
    publisher: Optional[str] = None
    product_name: Optional[str] = None
    file_version: Optional[str] = None
    raw: dict = Field(default_factory=dict)


class ApprovalIn(BaseModel):
    file_path: str
    policy_source_path: Optional[str] = None
    sha256: Optional[str] = None
    publisher: Optional[str] = None
    product_name: Optional[str] = None
    file_version: Optional[str] = None
    reason: Optional[str] = None
    requested_by: Optional[str] = None


class ApprovalComponentIn(BaseModel):
    file_path: str
    policy_source_path: Optional[str] = None
    sha256: Optional[str] = None
    publisher: Optional[str] = None
    product_name: Optional[str] = None
    file_version: Optional[str] = None
    parent_path: Optional[str] = None
    record_id: Optional[int] = None


class ApprovalSessionIn(BaseModel):
    components: list[ApprovalComponentIn]
    reason: Optional[str] = None
    requested_by: Optional[str] = None
    session_key: Optional[str] = None


def component_as_approval(component: ApprovalComponentIn) -> ApprovalIn:
    """Convert a grouped-request component into the single-file identity shape used by policy lookups.

    Grouped approval requests call the same approved/blocked identity matching helpers as single-file
    requests. Earlier 0.9/0.10 server builds referenced this adapter without defining it, causing an
    HTTP 500 whenever a user submitted a grouped Request Access form.
    """
    return ApprovalIn(
        file_path=component.file_path,
        policy_source_path=component.policy_source_path,
        sha256=component.sha256,
        publisher=component.publisher,
        product_name=component.product_name,
        file_version=component.file_version,
    )


class CommandComplete(BaseModel):
    success: bool
    claim_token: Optional[str] = None
    result: Optional[str] = None
    policy_id: Optional[str] = None
    rule_type: Optional[str] = None
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    publisher: Optional[str] = None
    product_name: Optional[str] = None
    file_version: Optional[str] = None


class OffboardComplete(BaseModel):
    success: bool
    result: Optional[str] = None


def hash_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()



def _session_hash(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _new_session(conn: sqlite3.Connection, user: sqlite3.Row, mfa_verified: bool) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=SESSION_HOURS)
    conn.execute("DELETE FROM web_sessions WHERE expires_at<?", (now.isoformat(),))
    conn.execute(
        "INSERT INTO web_sessions(token_hash,user_id,mfa_verified,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?)",
        (_session_hash(token), user['id'], 1 if mfa_verified else 0, now.isoformat(), now.isoformat(), expires.isoformat()),
    )
    return token


def _set_session_cookie(response: Response, token: str):
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_HOURS*3600, httponly=True,
                        secure=COOKIE_SECURE, samesite='lax', path='/')


def _clear_session_cookie(response: Response):
    response.delete_cookie(SESSION_COOKIE, path='/')


def _session_from_request(conn: sqlite3.Connection, request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    now = utcnow()
    row = conn.execute("SELECT * FROM web_sessions WHERE token_hash=? AND expires_at>?", (_session_hash(token), now)).fetchone()
    return row


def _same_origin_ok(request: Request) -> bool:
    if request.method.upper() in {'GET','HEAD','OPTIONS'}:
        return True
    host = (request.headers.get('host') or '').lower()
    origin = request.headers.get('origin')
    referer = request.headers.get('referer')
    candidate = origin or referer
    if not candidate:
        return True  # supports older/internal browsers; SameSite=Lax still protects normal cross-site POSTs.
    try:
        from urllib.parse import urlparse
        return (urlparse(candidate).netloc or '').lower() == host
    except Exception:
        return False


def _b32_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def _totp_code(secret: str, counter: int) -> str:
    padded = secret.upper() + '=' * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = counter.to_bytes(8, 'big')
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = ((digest[offset] & 0x7f) << 24) | (digest[offset+1] << 16) | (digest[offset+2] << 8) | digest[offset+3]
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str) -> bool:
    code = re.sub(r'\D', '', code or '')
    if len(code) != 6:
        return False
    counter = int(datetime.now(timezone.utc).timestamp() // 30)
    return any(hmac.compare_digest(_totp_code(secret, counter + skew), code) for skew in (-1,0,1))


def _recovery_hash(code: str) -> str:
    normalized = re.sub(r'[^A-Z0-9]', '', (code or '').upper())
    return hashlib.sha256(normalized.encode('ascii')).hexdigest()


def _new_recovery_codes() -> list[str]:
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    out=[]
    for _ in range(8):
        raw=''.join(secrets.choice(alphabet) for _ in range(12))
        out.append(raw[:4]+'-'+raw[4:8]+'-'+raw[8:])
    return out


def _verify_or_consume_mfa(conn: sqlite3.Connection, user: sqlite3.Row, code: str) -> tuple[bool,bool]:
    if user['mfa_secret'] and verify_totp(user['mfa_secret'], code):
        return True, False
    entered=_recovery_hash(code)
    try:
        hashes=json.loads(user['mfa_recovery_codes'] or '[]')
    except Exception:
        hashes=[]
    if entered in hashes:
        hashes.remove(entered)
        conn.execute('UPDATE users SET mfa_recovery_codes=? WHERE id=?',(json.dumps(hashes),user['id']))
        return True, True
    return False, False


def _auth_redirect(location: str):
    raise HTTPException(status_code=303, detail='Redirect', headers={'Location': location})


def agent_auth(
    x_device_id: str = Header(..., alias="X-Device-ID"),
    x_device_key: str = Header(..., alias="X-Device-Key"),
) -> str:
    with db() as conn:
        row = conn.execute("SELECT device_key_hash FROM devices WHERE id=?", (x_device_id,)).fetchone()
    if not row or not hmac.compare_digest(row["device_key_hash"], hash_key(x_device_key)):
        raise HTTPException(status_code=401, detail="Invalid device credentials")
    return x_device_id


def admin_auth(request: Request) -> Principal:
    if not _same_origin_ok(request):
        raise HTTPException(status_code=403, detail='Cross-site administrative request rejected.')
    with db() as conn:
        session = _session_from_request(conn, request)
        if not session:
            _auth_redirect('/login')
        row = conn.execute("SELECT * FROM users WHERE id=? AND deleted_at IS NULL", (session['user_id'],)).fetchone()
        if not row or not row['active']:
            if session:
                conn.execute('DELETE FROM web_sessions WHERE id=?',(session['id'],))
            _auth_redirect('/login')
        if row['mfa_enabled'] and not session['mfa_verified']:
            _auth_redirect('/login/mfa')
        allowed_force_paths={'/account/password','/logout'}
        if row['force_password_change'] and request.url.path not in allowed_force_paths:
            _auth_redirect('/account/password')
        conn.execute("UPDATE web_sessions SET last_seen=? WHERE id=?", (utcnow(), session['id']))
        return Principal(row['id'], row['username'], row['display_name'] or row['username'], row['role'], row['organization_id'], bool(row['force_password_change']))


def _menu(label: str, items: list[tuple[str, str]], extra_class: str = '') -> str:
    links = ''.join(f"<a href='{url}'>{escape(text)}</a>" for url, text in items)
    return f"<div class='nav-menu {extra_class}'><button class='nav-trigger' type='button'>{escape(label)} <span class='chev'>▾</span></button><div class='nav-dropdown'>{links}</div></div>"


def _side_link(url: str, label: str, icon: str = '•') -> str:
    return f"<a class='side-link' href='{url}'><span class='side-icon'>{escape(icon)}</span><span>{escape(label)}</span></a>"


def _side_section(label: str, items: list[tuple[str, str, str]]) -> str:
    if not items:
        return ''
    links=''.join(_side_link(url,text,icon) for url,text,icon in items)
    return f"<div class='side-section'><div class='side-label'>{escape(label)}</div>{links}</div>"


def nav(principal: Optional[Principal] = None) -> str:
    if not principal:
        return ''
    apps = [
        ('/approved', 'Approved Applications', '✓'),
        ('/learned', 'Learned / Observed', '◉'),
        ('/blocked', 'Explicit Blocks', '⊘'),
        ('/policies', 'Application Policies', '▤'),
    ]
    activity = [
        ('/requests', 'Approval Requests', '!'),
        ('/blocked-events', 'Blocked Activity', '×'),
        ('/commands', 'Command History', '↻'),
        ('/audit-log', 'Audit Log', '≡'),
    ]
    administration=[]
    if principal.can_manage_org:
        administration=[
            ('/organizations','Organizations & Groups','◆'),
            ('/agent-updates','Agent Updates','⇧'),
            ('/users','User Management','♙'),
        ]
        if principal.can_manage_global:
            administration.append(('/server-updates','Server Updates','⬆'))
    return (
        "<aside class='sidebar'><a class='side-brand' href='/'><span class='brand-mark'>AC</span><span><b>AppControl Manager</b><small>Application Control</small></span></a>"
        "<div class='side-scroll'>"
        + _side_section('Overview',[('/','Dashboard','⌂'),('/devices','Devices','▣'),('/reports','Reports','▥')])
        + _side_section('Applications',apps)
        + _side_section('Activity',activity)
        + (_side_section('Administration',administration) if administration else '')
        + "</div><div class='side-footer'>Server 0.15.0</div></aside>"
    )


def page(title: str, body: str, principal: Optional[Principal] = None, subtitle: str = '', actions: str = '') -> HTMLResponse:
    account=''
    search=''
    shell_class='auth-shell' if principal else 'login-shell'
    if principal:
        account=_menu(principal.display_name,[('/account','My Account'),('/account/security','Security / MFA'),('/account/password','Change Password'),('/logout','Sign Out')],'account-menu')
        account=f"<div class='account-wrap'>{account}<div class='role-label'>{escape(principal.role.replace('_',' ').title())}</div></div>"
        search="<form class='global-search' method='get' action='/search'><span>⌕</span><input name='q' placeholder='Search devices, applications, policies…' autocomplete='off'></form>"
    side=nav(principal)
    heading=''
    if principal:
        sub=f"<p>{escape(subtitle)}</p>" if subtitle else ''
        heading=f"<div class='page-heading'><div><h1>{escape(title)}</h1>{sub}</div><div class='heading-actions'>{actions}</div></div>"
    return HTMLResponse(f"""
<!doctype html><html><head><title>{escape(title)} - AppControl Manager</title>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<link rel='icon' href='/favicon.svg' type='image/svg+xml'>
<style>
:root{{--bg:#f4f6f9;--panel:#fff;--border:#dfe4ea;--text:#172033;--muted:#667085;--nav:#111827;--nav2:#1f2937;--primary:#2457d6;--primary2:#1d4ed8;--success:#067647;--danger:#b42318;--warning:#b54708}}
*{{box-sizing:border-box}} html,body{{min-height:100%}} body{{font-family:Segoe UI,system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);color:var(--text);font-size:14px}} .login-shell .workspace{{margin-left:0}}
a{{color:var(--primary);text-decoration:none}} a:hover{{text-decoration:underline}}
.app-shell{{min-height:100vh}} .sidebar{{position:fixed;inset:0 auto 0 0;width:252px;background:var(--nav);color:#dbe4f3;z-index:30;display:flex;flex-direction:column;border-right:1px solid #283548}}
.side-brand{{height:72px;padding:15px 18px;display:flex;align-items:center;gap:11px;color:#fff;border-bottom:1px solid #253044}} .side-brand:hover{{text-decoration:none;background:#182235}}
.side-brand b{{display:block;font-size:16px;letter-spacing:.1px}} .side-brand small{{display:block;color:#98a7bd;margin-top:2px;font-size:11px;font-weight:600}}
.brand-mark{{width:34px;height:34px;border-radius:9px;background:#2f6fed;color:white;display:inline-grid;place-items:center;font-size:12px;font-weight:800;box-shadow:inset 0 0 0 1px rgba(255,255,255,.22)}}
.side-scroll{{padding:13px 10px 24px;overflow-y:auto;flex:1}} .side-section{{margin-bottom:18px}} .side-label{{font-size:10px;font-weight:800;letter-spacing:.11em;text-transform:uppercase;color:#8493a9;padding:7px 10px}}
.side-link{{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:7px;color:#d5deea;font-weight:600;margin:1px 0}} .side-link:hover{{background:#243047;color:white;text-decoration:none}} .side-icon{{display:inline-grid;place-items:center;width:20px;color:#94a3b8;font-size:14px}}
.side-footer{{border-top:1px solid #253044;padding:12px 18px;color:#8090a7;font-size:11px}}
.workspace{{margin-left:252px;min-height:100vh}} .topbar{{height:72px;background:white;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:20px;padding:0 28px;position:sticky;top:0;z-index:20}}
.global-search{{height:38px;max-width:610px;width:min(48vw,610px);display:flex;align-items:center;gap:8px;border:1px solid #d4dae3;background:#f8fafc;border-radius:8px;padding:0 11px}} .global-search:focus-within{{background:#fff;border-color:#8aa8ef;box-shadow:0 0 0 3px rgba(36,87,214,.09)}} .global-search input{{border:0;outline:0;background:transparent;width:100%;padding:0;min-width:0}}
.account-wrap{{margin-left:auto;position:relative}} .nav-menu{{position:relative}} .nav-trigger{{border:0;background:transparent;padding:7px 10px;font-weight:700;color:#344054;cursor:pointer;border-radius:7px}} .nav-trigger:hover,.nav-menu:focus-within>.nav-trigger{{background:#f0f3f7}}
.nav-dropdown{{display:none;position:absolute;top:100%;right:0;min-width:205px;padding:6px;background:white;border:1px solid var(--border);border-radius:9px;box-shadow:0 14px 34px rgba(16,24,40,.16)}} .nav-menu:hover>.nav-dropdown,.nav-menu:focus-within>.nav-dropdown{{display:block}}
.nav-dropdown a{{display:block;color:#253247;padding:9px 10px;border-radius:6px;white-space:nowrap}} .nav-dropdown a:hover{{background:#eef3f8;text-decoration:none}} .role-label{{color:#7a889b;font-size:10px;padding-left:11px;margin-top:-5px;pointer-events:none}} .chev{{font-size:10px}}
main{{padding:26px 30px 44px;max-width:1780px;margin:auto}} .page-heading{{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:22px}} .page-heading h1{{font-size:27px;margin:0;color:#101828;letter-spacing:-.025em}} .page-heading p{{margin:6px 0 0;color:var(--muted);max-width:850px}} .heading-actions{{display:flex;gap:8px;flex-wrap:wrap}}
h2{{font-size:19px;margin-top:28px;color:#1d2939}} h3{{font-size:15px;color:#344054}}
.card,.panel{{background:white;border:1px solid var(--border);border-radius:11px;box-shadow:0 1px 2px rgba(16,24,40,.035)}} .card{{overflow:auto;margin-bottom:22px}} .panel{{padding:18px;margin-bottom:20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}} .grid-2{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}} .grid-3{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}}
.stat{{background:white;border:1px solid var(--border);border-radius:11px;padding:16px 17px;box-shadow:0 1px 2px rgba(16,24,40,.03)}} .stat-label{{font-size:12px;font-weight:700;color:#667085}} .stat b{{font-size:27px;display:block;margin:5px 0 2px;color:#101828;letter-spacing:-.03em}} .stat .trend{{font-size:12px;color:#667085}}
.metric-row{{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:11px 0;border-bottom:1px solid #edf0f4}} .metric-row:last-child{{border-bottom:0}} .metric-value{{font-weight:750}}
.progress{{height:8px;border-radius:999px;background:#edf1f5;overflow:hidden}} .progress>span{{display:block;height:100%;background:#4f7de5;border-radius:999px}} .progress.danger>span{{background:#d92d20}} .progress.success>span{{background:#12b76a}}
.bar-list{{padding:4px 0}} .bar-row{{display:grid;grid-template-columns:minmax(100px,180px) 1fr 48px;gap:10px;align-items:center;margin:10px 0}} .bar-track{{height:9px;border-radius:999px;background:#edf1f5;overflow:hidden}} .bar-fill{{height:100%;background:#5d7ee8;border-radius:999px;min-width:2px}}
.spark-bars{{display:flex;align-items:flex-end;gap:5px;height:100px;padding:10px 4px 3px}} .spark-bar-wrap{{display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:5px;flex:1;height:100%}} .spark-bar{{width:100%;max-width:32px;background:#5d7ee8;border-radius:4px 4px 1px 1px;min-height:2px}} .spark-label{{font-size:10px;color:#7a889b;white-space:nowrap}}
table{{border-collapse:separate;border-spacing:0;width:100%;background:white}} th,td{{padding:11px 12px;border-bottom:1px solid #e7ebf0;text-align:left;vertical-align:top}} th{{background:#f7f9fb;color:#475467;font-size:11px;text-transform:uppercase;letter-spacing:.035em;white-space:nowrap;font-weight:800}} tbody tr:hover td{{background:#fafcff}} tr:last-child td{{border-bottom:0}} .compact td{{padding:8px 10px}}
button,.button{{padding:8px 12px;border:1px solid #b8c1cd;border-radius:7px;background:white;cursor:pointer;font-weight:650;color:#344054;display:inline-block}} button:hover,.button:hover{{background:#f3f5f8;text-decoration:none}} .btn-primary{{background:var(--primary);color:white;border-color:var(--primary)}} .btn-primary:hover{{background:#1948bc}} .btn-danger{{background:#b42318;color:white;border-color:#b42318}} .btn-danger:hover{{background:#912018}} .btn-warning{{background:#f79009;color:white;border-color:#f79009}} .btn-warning:hover{{background:#dc7600}} .btn-quiet{{border-color:transparent;background:#f1f4f7}}
input,select,textarea{{padding:8px 10px;border:1px solid #cbd3df;border-radius:7px;min-width:180px;background:white;color:#182230}} input:focus,select:focus,textarea:focus{{outline:0;border-color:#7c9cf0;box-shadow:0 0 0 3px rgba(36,87,214,.09)}} label{{font-size:12px;font-weight:700;color:#475467}} .field{{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}}
code{{font-size:12px;word-break:break-all}} .muted{{color:#667085;font-size:12px}} .badge{{display:inline-block;padding:4px 8px;border-radius:999px;background:#e9edf3;color:#475467;font-size:11px;font-weight:750;white-space:nowrap}} .badge-ok{{background:#dcfae6;color:#067647}} .badge-bad{{background:#fee4e2;color:#b42318}} .badge-warn{{background:#fef0c7;color:#b54708}} .badge-info{{background:#e8f0ff;color:#2457d6}}
.actions{{display:flex;gap:7px;flex-wrap:wrap;align-items:center}} .copy-wrap{{display:flex;align-items:center;gap:7px;min-width:0}} .copy-wrap code{{display:block;max-width:640px;padding:7px 9px;background:#f7f9fb;border:1px solid #e1e6ed;border-radius:6px;word-break:break-all}} .copy-btn{{padding:6px 9px;font-size:12px;white-space:nowrap}} .notice,.notice-warn{{background:#fff7e6;border:1px solid #fedf89;padding:12px 14px;border-radius:8px;margin-bottom:18px}} .notice-info{{background:#eff6ff;border:1px solid #bfdbfe;padding:12px 14px;border-radius:8px;margin-bottom:18px;color:#1e40af}}
.scope-select{{min-width:145px}} .section-head{{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:28px 0 10px}} .section-head h2{{margin:0}}
.filters{{display:flex;flex-wrap:wrap;gap:10px;align-items:end;background:white;border:1px solid var(--border);border-radius:10px;padding:13px;margin-bottom:16px}} .filters .field{{margin:0}} .filters input,.filters select{{min-width:145px}}
.pagination{{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:11px 13px;background:white;border:1px solid var(--border);border-radius:9px;margin:12px 0 22px}} .pagination .pages{{display:flex;gap:6px}}
.app-cell b{{display:block;color:#182230}} .file-sub{{font-family:Consolas,monospace;font-size:11px;color:#667085;margin-top:3px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}} .publisher-short{{max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}} .clip{{display:block;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}} .nowrap{{white-space:nowrap}}
.details-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}} .detail-item{{padding:10px 0;border-bottom:1px solid #edf0f4}} .detail-item .muted{{display:block;margin-bottom:4px}} .table-actions{{min-width:240px}} .action-stack{{display:flex;flex-direction:column;gap:10px;align-items:flex-start}} .block-action{{padding-top:9px;border-top:1px solid #e5e9ef;width:100%}} .action-label{{display:block;font-size:11px;font-weight:750;color:#667085;margin-bottom:5px}}
.empty{{padding:34px;text-align:center;color:#667085}} .kicker{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;font-weight:800;color:#667085}} .callout{{padding:15px;border-radius:10px;background:#f8fafc;border:1px solid #e4e8ee}}
.report-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:15px}} .report-card{{display:block;background:white;border:1px solid var(--border);border-radius:11px;padding:18px;color:#182230;box-shadow:0 1px 2px rgba(16,24,40,.03)}} .report-card:hover{{border-color:#aebee5;box-shadow:0 4px 14px rgba(16,24,40,.07);text-decoration:none}} .report-card h3{{margin:2px 0 7px}} .report-card p{{margin:0;color:#667085;font-size:12px;line-height:1.5}} .report-icon{{font-size:22px;margin-bottom:8px;color:#315fcb}}
.report-header{{padding:18px 20px;background:#fff;border:1px solid var(--border);border-radius:11px;margin-bottom:18px}} .report-title{{font-size:22px;font-weight:800;margin:0}} .report-meta{{color:#667085;margin-top:6px;font-size:12px}} .print-only{{display:none}}
.login-shell{{min-height:100vh;background:#f5f7fa}} .login-wrap{{max-width:430px;margin:0 auto;padding-top:70px}} .login-wrap .panel{{padding:26px}} .qr{{background:white;padding:12px;border:1px solid #dde3eb;border-radius:10px;display:inline-block}}
@media(max-width:1100px){{.grid-2,.grid-3{{grid-template-columns:1fr}}}}
@media(max-width:850px){{.sidebar{{position:static;width:100%;height:auto}}.side-scroll{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));max-height:none}}.side-footer{{display:none}}.workspace{{margin-left:0}}.topbar{{position:static;padding:0 14px}}.global-search{{width:100%;max-width:none}}main{{padding:20px 14px}}.page-heading{{flex-direction:column}}}}
@media print{{body{{background:white}}.sidebar,.topbar,.filters,.pagination,.no-print,.heading-actions,.page-heading{{display:none!important}}.workspace{{margin:0}}main{{padding:0;max-width:none}}.page-heading{{margin-bottom:14px}}.card,.panel,.stat{{box-shadow:none;break-inside:avoid}}.print-only{{display:block}}a{{color:inherit;text-decoration:none}}}}
</style><script>
function acmCopy(id,button){{
  const el=document.getElementById(id); if(!el) return;
  const text=el.getAttribute('data-copy') || el.textContent || '';
  const done=()=>{{ const old=button.textContent; button.textContent='Copied'; setTimeout(()=>button.textContent=old,1400); }};
  const fallback=()=>{{ const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.focus(); ta.select(); try{{document.execCommand('copy');done();}}finally{{document.body.removeChild(ta);}} }};
  if(navigator.clipboard && window.isSecureContext){{navigator.clipboard.writeText(text).then(done).catch(fallback);}}else{{fallback();}}
}}
</script></head><body class='{shell_class}'>{side}<div class='workspace'>{("<div class='topbar'>"+search+account+"</div>") if principal else ''}<main>{heading}{body}</main></div></body></html>""")


def display_mode(row: sqlite3.Row) -> str:
    mode = (row["policy_mode"] or "").lower() if "policy_mode" in row.keys() else ""
    if mode == "learning":
        return "Learning"
    if mode == "enforcement":
        return "Enforcement"
    if mode == "unknown":
        return "Unknown"
    return "Learning" if row["learning_mode"] else "Enforcement"


def _product_family_match(row: sqlite3.Row, req: ApprovalIn) -> bool:
    rule = (row["rule_type"] or "").lower() if "rule_type" in row.keys() else ""
    if "product family" not in rule:
        return False
    return bool(
        req.publisher and req.product_name and row["publisher"] and row["product_name"]
        and req.publisher == row["publisher"]
        and req.product_name == row["product_name"]
    )


def find_existing_approved(conn: sqlite3.Connection, device_id: str, req: ApprovalIn):
    # Exact content is always a safe duplicate match.
    if req.sha256:
        row = conn.execute(
            "SELECT * FROM approved_components WHERE device_id=? AND sha256=? AND COALESCE(status,'approved')='approved' ORDER BY id DESC LIMIT 1",
            (device_id, req.sha256),
        ).fetchone()
        if row:
            return row
        row = conn.execute(
            "SELECT * FROM approved_applications WHERE device_id=? AND sha256=? AND COALESCE(status,'approved')='approved' ORDER BY id DESC LIMIT 1",
            (device_id, req.sha256),
        ).fetchone()
        if row:
            return row

    # ProductName-scoped FilePublisher approvals intentionally cover sibling EXEs/DLLs
    # that share the same signed publisher and product identity.
    if req.publisher and req.product_name:
        rows = conn.execute(
            "SELECT * FROM approved_components WHERE device_id=? AND publisher=? AND product_name=? AND COALESCE(status,'approved')='approved' ORDER BY id DESC",
            (device_id, req.publisher, req.product_name),
        ).fetchall()
        rows += conn.execute(
            "SELECT * FROM approved_applications WHERE device_id=? AND publisher=? AND product_name=? AND COALESCE(status,'approved')='approved' ORDER BY id DESC",
            (device_id, req.publisher, req.product_name),
        ).fetchall()
        for row in rows:
            if _product_family_match(row, req):
                return row

    # A changed file at the same path is only considered covered when the
    # prior approval was publisher-based and the publisher still matches.
    rows = conn.execute(
        "SELECT * FROM approved_components WHERE device_id=? AND lower(file_path)=lower(?) AND COALESCE(status,'approved')='approved' ORDER BY id DESC",
        (device_id, req.file_path),
    ).fetchall()
    rows += conn.execute(
        "SELECT * FROM approved_applications WHERE device_id=? AND lower(file_path)=lower(?) AND COALESCE(status,'approved')='approved' ORDER BY id DESC",
        (device_id, req.file_path),
    ).fetchall()
    for row in rows:
        rule = (row["rule_type"] or "").lower()
        if "publisher" in rule and req.publisher and row["publisher"] and req.publisher == row["publisher"]:
            return row
    return None


def find_existing_block(conn: sqlite3.Connection, device_id: str, req: ApprovalIn):
    if req.sha256:
        row = conn.execute(
            "SELECT * FROM blocked_applications WHERE device_id=? AND sha256=? AND status IN ('blocking','blocked','unblocking') ORDER BY id DESC LIMIT 1",
            (device_id, req.sha256),
        ).fetchone()
        if row:
            return row

    if req.publisher and req.product_name:
        rows = conn.execute(
            "SELECT * FROM blocked_applications WHERE device_id=? AND publisher=? AND product_name=? AND status IN ('blocking','blocked','unblocking') ORDER BY id DESC",
            (device_id, req.publisher, req.product_name),
        ).fetchall()
        for row in rows:
            if _product_family_match(row, req):
                return row

    return conn.execute(
        "SELECT * FROM blocked_applications WHERE device_id=? AND lower(file_path)=lower(?) AND status IN ('blocking','blocked','unblocking') ORDER BY id DESC LIMIT 1",
        (device_id, req.file_path),
    ).fetchone()


def find_revoked_approval(conn: sqlite3.Connection, device_id: str, req: ApprovalIn):
    if req.sha256:
        row = conn.execute(
            "SELECT * FROM approved_components WHERE device_id=? AND sha256=? AND status='revoked' ORDER BY id DESC LIMIT 1",
            (device_id, req.sha256),
        ).fetchone()
        if row:
            return row
        row = conn.execute(
            "SELECT * FROM approved_applications WHERE device_id=? AND sha256=? AND status='revoked' ORDER BY id DESC LIMIT 1",
            (device_id, req.sha256),
        ).fetchone()
        if row:
            return row

    if req.publisher and req.product_name:
        rows = conn.execute(
            "SELECT * FROM approved_components WHERE device_id=? AND publisher=? AND product_name=? AND status='revoked' ORDER BY id DESC",
            (device_id, req.publisher, req.product_name),
        ).fetchall()
        rows += conn.execute(
            "SELECT * FROM approved_applications WHERE device_id=? AND publisher=? AND product_name=? AND status='revoked' ORDER BY id DESC",
            (device_id, req.publisher, req.product_name),
        ).fetchall()
        for row in rows:
            if _product_family_match(row, req):
                return row

    rows = conn.execute(
        "SELECT * FROM approved_components WHERE device_id=? AND lower(file_path)=lower(?) AND status='revoked' ORDER BY id DESC",
        (device_id, req.file_path),
    ).fetchall()
    rows += conn.execute(
        "SELECT * FROM approved_applications WHERE device_id=? AND lower(file_path)=lower(?) AND status='revoked' ORDER BY id DESC",
        (device_id, req.file_path),
    ).fetchall()
    return rows[0] if rows else None


def find_active_overlapping_request(conn: sqlite3.Connection, device_id: str, requested_by: Optional[str], components: list[ApprovalComponentIn]):
    hashes = {((c.sha256 or "").strip().lower()) for c in components if (c.sha256 or "").strip()}
    paths = {((c.file_path or "").strip().lower()) for c in components if (c.file_path or "").strip()}
    if not hashes and not paths:
        return None

    params: list[object] = [device_id]
    requester_sql = ""
    if requested_by:
        requester_sql = " AND (r.requested_by=? OR r.requested_by IS NULL OR r.requested_by='')"
        params.append(requested_by)

    rows = conn.execute(
        f"""SELECT r.id,r.status,r.file_path AS request_path,r.sha256 AS request_sha256,
                   i.original_path AS item_path,i.sha256 AS item_sha256
            FROM approval_requests r
            LEFT JOIN approval_request_items i ON i.request_id=r.id
            WHERE r.device_id=? AND r.status IN ('pending','approving'){requester_sql}
            ORDER BY r.id DESC""",
        params,
    ).fetchall()

    for row in rows:
        candidate_hashes = {
            (row["request_sha256"] or "").strip().lower(),
            (row["item_sha256"] or "").strip().lower(),
        } - {""}
        candidate_paths = {
            (row["request_path"] or "").strip().lower(),
            (row["item_path"] or "").strip().lower(),
        } - {""}
        if hashes.intersection(candidate_hashes) or paths.intersection(candidate_paths):
            return row
    return None


@app.get('/favicon.svg', include_in_schema=False)
def favicon():
    svg = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>
    <rect width='64' height='64' rx='14' fill='#2457d6'/>
    <path d='M32 11 50 18v13c0 12-7.4 19.9-18 23-10.6-3.1-18-11-18-23V18l18-7Z' fill='white' opacity='.97'/>
    <path d='m23 32 6 6 13-15' fill='none' stroke='#2457d6' stroke-width='5' stroke-linecap='round' stroke-linejoin='round'/>
    </svg>"""
    return Response(content=svg, media_type='image/svg+xml', headers={'Cache-Control':'public, max-age=86400'})



@app.get('/login', response_class=HTMLResponse)
def login_page(error:str=''):
    note=f"<div class='notice-warn'>{escape(error)}</div>" if error else ''
    body=f"<div class='login-wrap'><div class='panel'>{note}<h2 style='margin-top:0'>Sign in</h2><form method='post' action='/login'><div class='field'><label>Username</label><input name='username' autocomplete='username' required autofocus></div><div class='field'><label>Password</label><input type='password' name='password' autocomplete='current-password' required></div><button class='btn-primary' style='width:100%'>Sign in</button></form></div></div>"
    return page('Sign in',body,None)


@app.post('/login')
def login_submit(username:str=Form(...), password:str=Form(...)):
    with db() as conn:
        user=conn.execute("SELECT * FROM users WHERE lower(username)=lower(?) AND deleted_at IS NULL",(username.strip(),)).fetchone()
        if not user or not user['active'] or not password_verify(password,user['password_hash']):
            return RedirectResponse('/login?'+urlencode({'error':'Invalid username or password.'}),status_code=303)
        token=_new_session(conn,user,not bool(user['mfa_enabled']))
        target='/login/mfa' if user['mfa_enabled'] else ('/account/password' if user['force_password_change'] else '/')
        if not user['mfa_enabled']:
            conn.execute('UPDATE users SET last_login=? WHERE id=?',(utcnow(),user['id']))
            audit(conn,user['username'],'login',organization_id=user['organization_id'],object_type='user',object_id=user['id'])
    response=RedirectResponse(target,status_code=303)
    _set_session_cookie(response,token)
    return response


@app.get('/login/mfa', response_class=HTMLResponse)
def login_mfa_page(request:Request, error:str=''):
    with db() as conn:
        session=_session_from_request(conn,request)
        if not session: return RedirectResponse('/login',status_code=303)
        user=conn.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone()
        if not user or not user['active']: return RedirectResponse('/login',status_code=303)
        if not user['mfa_enabled']: return RedirectResponse('/',status_code=303)
    note=f"<div class='notice-warn'>{escape(error)}</div>" if error else ''
    body=f"<div class='login-wrap'><div class='panel'>{note}<h2 style='margin-top:0'>Two-factor authentication</h2><p class='muted'>Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p><form method='post' action='/login/mfa'><div class='field'><label>Authentication code</label><input name='code' inputmode='numeric' autocomplete='one-time-code' required autofocus></div><button class='btn-primary' style='width:100%'>Verify</button></form></div></div>"
    return page('Two-factor authentication',body,None)


@app.post('/login/mfa')
def login_mfa_submit(request:Request, code:str=Form(...)):
    with db() as conn:
        session=_session_from_request(conn,request)
        if not session: return RedirectResponse('/login',status_code=303)
        user=conn.execute('SELECT * FROM users WHERE id=? AND deleted_at IS NULL',(session['user_id'],)).fetchone()
        if not user or not user['active']: return RedirectResponse('/login',status_code=303)
        ok,recovery=_verify_or_consume_mfa(conn,user,code)
        if not ok:
            return RedirectResponse('/login/mfa?'+urlencode({'error':'The authentication code was not accepted.'}),status_code=303)
        conn.execute('UPDATE web_sessions SET mfa_verified=1,last_seen=? WHERE id=?',(utcnow(),session['id']))
        conn.execute('UPDATE users SET last_login=? WHERE id=?',(utcnow(),user['id']))
        audit(conn,user['username'],'login_mfa_recovery' if recovery else 'login_mfa',organization_id=user['organization_id'],object_type='user',object_id=user['id'])
        target='/account/password' if user['force_password_change'] else '/'
    return RedirectResponse(target,status_code=303)


@app.get('/logout')
def logout(request:Request):
    token=request.cookies.get(SESSION_COOKIE)
    if token:
        with db() as conn:
            session=conn.execute('SELECT user_id FROM web_sessions WHERE token_hash=?',(_session_hash(token),)).fetchone()
            if session:
                user=conn.execute('SELECT username,organization_id FROM users WHERE id=?',(session['user_id'],)).fetchone()
                if user: audit(conn,user['username'],'logout',organization_id=user['organization_id'],object_type='user',object_id=session['user_id'])
            conn.execute('DELETE FROM web_sessions WHERE token_hash=?',(_session_hash(token),))
    response=RedirectResponse('/login',status_code=303)
    _clear_session_cookie(response)
    return response


@app.get('/account/security', response_class=HTMLResponse)
def account_security(request:Request, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        user=conn.execute('SELECT * FROM users WHERE id=?',(principal.id,)).fetchone()
    if user['mfa_enabled']:
        body="""<div class='panel'><h2 style='margin-top:0'>Two-factor authentication</h2><p><span class='badge badge-ok'>Enabled</span></p><p class='muted'>TOTP MFA is required after your password when starting a new AppControl Manager web session.</p><h3>Disable MFA</h3><form method='post' action='/account/mfa/disable'><div class='field'><label>Current password</label><input type='password' name='password' required></div><div class='field'><label>Authenticator code</label><input name='code' inputmode='numeric' required></div><button class='btn-danger'>Disable MFA</button></form></div>"""
    else:
        body="""<div class='panel'><h2 style='margin-top:0'>Two-factor authentication</h2><p><span class='badge'>Not configured</span></p><p class='muted'>Use any standard TOTP authenticator such as Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden, or similar.</p><form method='post' action='/account/mfa/start'><button class='btn-primary'>Set up MFA</button></form></div>"""
    return page('Security / MFA',body,principal)


@app.post('/account/mfa/start')
def mfa_start(request:Request, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        session=_session_from_request(conn,request)
        if not session: _auth_redirect('/login')
        user=conn.execute('SELECT mfa_enabled FROM users WHERE id=?',(principal.id,)).fetchone()
        if user and user['mfa_enabled']: return RedirectResponse('/account/security',status_code=303)
        conn.execute('UPDATE web_sessions SET pending_mfa_secret=? WHERE id=?',(_b32_secret(),session['id']))
    return RedirectResponse('/account/mfa/setup',status_code=303)


@app.get('/account/mfa/setup', response_class=HTMLResponse)
def mfa_setup(request:Request, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        session=_session_from_request(conn,request)
        secret=session['pending_mfa_secret'] if session else None
    if not secret: return RedirectResponse('/account/security',status_code=303)
    body=f"""<div class='panel'><h2 style='margin-top:0'>Set up authenticator</h2><ol><li>Scan this QR code with your authenticator app.</li><li>Enter the 6-digit code below to verify enrollment.</li></ol><div class='qr'><img src='/account/mfa/qr' width='220' height='220' alt='TOTP QR code'></div><p class='muted'>Manual setup key: <code>{escape(secret)}</code></p><form method='post' action='/account/mfa/verify'><div class='field'><label>6-digit code</label><input name='code' inputmode='numeric' autocomplete='one-time-code' required autofocus></div><button class='btn-primary'>Enable MFA</button></form></div>"""
    return page('Set up MFA',body,principal)


@app.get('/account/mfa/qr')
def mfa_qr(request:Request, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        session=_session_from_request(conn,request)
        secret=session['pending_mfa_secret'] if session else None
    if not secret: raise HTTPException(status_code=404,detail='No MFA enrollment in progress')
    label=quote(f'AppControl Manager:{principal.username}')
    uri=f'otpauth://totp/{label}?secret={secret}&issuer={quote("AppControl Manager")}&digits=6&period=30'
    img=qrcode.make(uri)
    buf=io.BytesIO(); img.save(buf,format='PNG')
    return Response(buf.getvalue(),media_type='image/png',headers={'Cache-Control':'no-store'})


@app.post('/account/mfa/verify', response_class=HTMLResponse)
def mfa_verify(request:Request, code:str=Form(...), principal:Principal=Depends(admin_auth)):
    with db() as conn:
        session=_session_from_request(conn,request)
        secret=session['pending_mfa_secret'] if session else None
        if not secret or not verify_totp(secret,code):
            raise HTTPException(status_code=400,detail='The authenticator code was not accepted.')
        recovery=_new_recovery_codes()
        hashes=[_recovery_hash(x) for x in recovery]
        conn.execute('UPDATE users SET mfa_enabled=1,mfa_secret=?,mfa_recovery_codes=? WHERE id=?',(secret,json.dumps(hashes),principal.id))
        conn.execute('UPDATE web_sessions SET mfa_verified=1,pending_mfa_secret=NULL WHERE id=?',(session['id'],))
        audit(conn,principal.username,'mfa_enabled',organization_id=principal.organization_id,object_type='user',object_id=principal.id)
    codes='<br>'.join(f'<code>{escape(x)}</code>' for x in recovery)
    body=f"<div class='notice'><b>MFA is enabled.</b></div><div class='panel'><h2 style='margin-top:0'>Save your recovery codes</h2><p>Each recovery code can be used once if your authenticator is unavailable. Store them somewhere secure; AppControl Manager will not display them again.</p><div style='line-height:2'>{codes}</div><p style='margin-top:18px'><a href='/account/security'><button class='btn-primary'>Done</button></a></p></div>"
    return page('MFA enabled',body,principal)


@app.post('/account/mfa/disable')
def mfa_disable(password:str=Form(...), code:str=Form(...), principal:Principal=Depends(admin_auth)):
    with db() as conn:
        user=conn.execute('SELECT * FROM users WHERE id=?',(principal.id,)).fetchone()
        if not user or not password_verify(password,user['password_hash']): raise HTTPException(status_code=400,detail='Current password is incorrect.')
        ok,_=_verify_or_consume_mfa(conn,user,code)
        if not ok: raise HTTPException(status_code=400,detail='Authenticator code was not accepted.')
        conn.execute('UPDATE users SET mfa_enabled=0,mfa_secret=NULL,mfa_recovery_codes=NULL WHERE id=?',(principal.id,))
        audit(conn,principal.username,'mfa_disabled',organization_id=principal.organization_id,object_type='user',object_id=principal.id)
    return RedirectResponse('/account/security',status_code=303)


@app.get("/health")
def health():
    return {"ok": True, "version": "0.15.0"}


@app.post("/api/enroll", response_model=EnrollResponse)
def enroll(req: EnrollRequest):
    token_hash = hash_key(req.enrollment_token)
    with db() as conn:
        key = conn.execute(
            """SELECT k.*,o.status AS org_status FROM enrollment_keys k JOIN organizations o ON o.id=k.organization_id
               WHERE k.token_hash=? AND k.active=1""", (token_hash,)
        ).fetchone()
        if not key or key['org_status'] != 'active':
            raise HTTPException(status_code=403, detail="Invalid enrollment token")
        device_id = secrets.token_hex(16)
        device_key = secrets.token_urlsafe(32)
        conn.execute(
            """INSERT INTO devices(id,hostname,device_key_hash,os_version,learning_mode,policy_mode,last_seen,created_at,organization_id)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (device_id, req.hostname, hash_key(device_key), req.os_version, 0, "unknown", utcnow(), utcnow(), key['organization_id']),
        )
        conn.execute("UPDATE enrollment_keys SET last_used_at=? WHERE id=?", (utcnow(), key['id']))
        audit(conn, 'enrollment', 'device_enrolled', organization_id=key['organization_id'], device_id=device_id,
              object_type='device', object_id=device_id, detail=req.hostname)
    return EnrollResponse(device_id=device_id, device_key=device_key)


@app.post("/api/heartbeat")
def heartbeat(req: HeartbeatRequest, device_id: str = Depends(agent_auth)):
    mode = (req.policy_mode or "").strip().lower()
    if mode not in {"learning", "enforcement", "unknown"}:
        if req.learning_mode is None:
            mode = "unknown"
        else:
            mode = "learning" if req.learning_mode else "enforcement"
    learning = req.learning_mode if req.learning_mode is not None else (mode == "learning")
    with db() as conn:
        conn.execute(
            """UPDATE devices SET last_seen=?,learning_mode=?,policy_mode=?,
               script_enforcement_disabled=COALESCE(?,script_enforcement_disabled),
               agent_version=COALESCE(?,agent_version),os_version=COALESCE(?,os_version),
               update_status=COALESCE(?,update_status),update_result=COALESCE(?,update_result) WHERE id=?""",
            (
                utcnow(), 1 if learning else 0, mode,
                None if req.script_enforcement_disabled is None else (1 if req.script_enforcement_disabled else 0),
                req.agent_version, req.os_version, req.update_status, req.update_result, device_id,
            ),
        )
        if req.update_status in {'installed','rolled_back','failed'}:
            conn.execute("UPDATE devices SET last_update_at=? WHERE id=?",(utcnow(),device_id))
            if req.update_status in {'rolled_back','failed'}:
                desired=conn.execute('SELECT desired_agent_version FROM devices WHERE id=?',(device_id,)).fetchone()
                if desired and desired['desired_agent_version']:
                    conn.execute("UPDATE agent_update_history SET status=?,detail=?,completed_at=? WHERE device_id=? AND target_version=? AND status IN ('queued','installing')",(req.update_status,req.update_result,utcnow(),device_id,desired['desired_agent_version']))
        refresh_device_update_target(conn,device_id)
    return {"ok": True}


@app.get('/api/agent/releases/{release_id}/download')
def download_agent_release(release_id: int, device_id: str = Depends(agent_auth)):
    with db() as conn:
        release=conn.execute('SELECT * FROM agent_releases WHERE id=? AND active=1 AND deleted_at IS NULL',(release_id,)).fetchone()
        if not release: raise HTTPException(status_code=404,detail='Agent release not found')
        allowed=False
        for row in conn.execute("SELECT payload FROM commands WHERE device_id=? AND command_type='update_agent' AND status IN ('processing','completed') ORDER BY id DESC LIMIT 10",(device_id,)).fetchall():
            try:
                if int(json.loads(row['payload']).get('release_id') or 0)==release_id: allowed=True; break
            except Exception: pass
        if not allowed: raise HTTPException(status_code=403,detail='This release is not assigned to the device.')
        path=Path(release['file_path'])
        if not path.is_file(): raise HTTPException(status_code=404,detail='Release package is missing on the server.')
        return FileResponse(path,media_type='application/zip',filename=release['file_name'])


@app.post("/api/events")
def post_events(events: list[EventIn], device_id: str = Depends(agent_auth)):
    with db() as conn:
        count = 0
        for e in events:
            cur = conn.execute(
                """INSERT INTO events(device_id,event_id,record_id,occurred_at,file_path,parent_path,sha256,publisher,product_name,file_version,raw_json,received_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    device_id, e.event_id, e.record_id, e.occurred_at, e.file_path, e.parent_path,
                    e.sha256, e.publisher, e.product_name, e.file_version, json.dumps(e.raw), utcnow(),
                ),
            )
            count += cur.rowcount
            if e.event_id == 3077 and e.file_path:
                scoped_block = find_scoped_policy(conn, device_id, e, 'block')
                if scoped_block:
                    ensure_scoped_block_on_device(conn, device_id, e, scoped_block)
    return {"ok": True, "count": count}


@app.post("/api/disposition")
def application_disposition(req: ApprovalIn, device_id: str = Depends(agent_auth)):
    """Return how the tray should present a WDAC block without creating a request."""
    with db() as conn:
        scoped_block = find_scoped_policy(conn, device_id, req, 'block')
        if scoped_block:
            ensure_scoped_block_on_device(conn, device_id, req, scoped_block)
            return {"ok": True, "state": "blocked", "policy_id": f"scope-{scoped_block['id']}",
                    "decision_note": f"Blocked by {scoped_block['scope_type']} policy #{scoped_block['id']}."}
        blocked = find_existing_block(conn, device_id, req)
        if blocked:
            return {
                "ok": True, "state": "blocked",
                "policy_id": blocked["policy_id"],
                "decision_note": blocked["note"] or "This application is explicitly blocked by an administrator.",
            }

        scoped_allow = find_scoped_policy(conn, device_id, req, 'allow')
        if scoped_allow:
            auto_request_id = queue_scoped_auto_approval(conn, device_id, req, scoped_allow, req.requested_by)
            if auto_request_id:
                return {"ok": True, "state": "active_request", "request_id": auto_request_id, "request_status": "approving",
                        "decision_note": f"Automatically approved by {scoped_allow['scope_type']} policy #{scoped_allow['id']}."}

        active = find_active_overlapping_request(conn, device_id, req.requested_by, [ApprovalComponentIn(
            file_path=req.file_path, policy_source_path=req.policy_source_path, sha256=req.sha256,
            publisher=req.publisher, product_name=req.product_name, file_version=req.file_version
        )])
        if active:
            return {"ok": True, "state": "active_request", "request_id": active["id"], "request_status": active["status"]}

        revoked = find_revoked_approval(conn, device_id, req)
        if revoked:
            return {
                "ok": True, "state": "revoked",
                "policy_id": revoked["policy_id"],
                "decision_note": "A previous AppControl Manager approval for this application was revoked.",
            }

        approved = find_existing_approved(conn, device_id, req)
        if approved:
            return {
                "ok": True, "state": "approved",
                "policy_id": approved["policy_id"], "rule_type": approved["rule_type"],
            }

    return {"ok": True, "state": "unknown"}


@app.post("/api/blocks/user")
def create_user_device_block(req: ApprovalIn, device_id: str = Depends(agent_auth)):
    """Create a device-only explicit block requested by the interactive endpoint user.

    Endpoint users are intentionally limited to their own enrolled device. This does not create
    a group, organization, or global scoped policy. As soon as the blocking row exists, disposition
    checks treat future attempts as explicit blocks (silent on the endpoint) while the local deny
    policy is being generated.
    """
    actor = (req.requested_by or "endpoint-user").strip() or "endpoint-user"
    with db() as conn:
        device = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        existing = find_existing_block(conn, device_id, req)
        if existing:
            return {
                "ok": True, "state": existing["status"], "blocked": True,
                "policy_id": existing["policy_id"],
                "decision_note": "This application is already explicitly blocked on this device.",
            }

        reason = (req.reason or "").strip()
        note = f"Device-only block requested by endpoint user {actor}."
        if reason:
            note += f" User note: {reason}"
        block_id = _queue_block(
            conn, device_id=device_id, file_path=req.file_path, policy_source_path=req.policy_source_path,
            sha256=req.sha256, publisher=req.publisher, product_name=req.product_name, file_version=req.file_version,
            admin_user=actor, block_note=note,
        )
        audit(conn, actor, 'endpoint_user_block_created', organization_id=device['organization_id'], device_id=device_id,
              object_type='blocked_application', object_id=block_id, detail=f"device-only block; file={req.file_path}")
        return {
            "ok": True, "state": "blocking", "blocked": True,
            "decision_note": "Blocked on this device. Future attempts will be silently blocked and logged.",
        }


@app.post("/api/requests")
def create_request(req: ApprovalIn, device_id: str = Depends(agent_auth)):
    with db() as conn:
        scoped_block = find_scoped_policy(conn, device_id, req, 'block')
        if scoped_block:
            ensure_scoped_block_on_device(conn, device_id, req, scoped_block)
            return {"ok": True, "blocked": True, "status": "blocked", "policy_id": f"scope-{scoped_block['id']}",
                    "decision_note": f"Blocked by {scoped_block['scope_type']} policy #{scoped_block['id']}."}
        blocked = find_existing_block(conn, device_id, req)
        if blocked:
            return {
                "ok": True, "blocked": True, "status": "blocked",
                "policy_id": blocked["policy_id"],
                "decision_note": blocked["note"] or "This application is explicitly blocked by an administrator.",
            }
        approved = find_existing_approved(conn, device_id, req)
        if approved:
            return {
                "ok": True, "already_approved": True, "request_id": approved["request_id"],
                "policy_id": approved["policy_id"], "rule_type": approved["rule_type"],
            }

        scoped_allow = find_scoped_policy(conn, device_id, req, 'allow')
        if scoped_allow:
            auto_request_id = queue_scoped_auto_approval(conn, device_id, req, scoped_allow, req.requested_by)
            if auto_request_id:
                return {"ok": True, "duplicate": True, "request_id": auto_request_id, "status": "approving"}

        active = find_active_overlapping_request(conn, device_id, req.requested_by, [ApprovalComponentIn(
            file_path=req.file_path, policy_source_path=req.policy_source_path, sha256=req.sha256,
            publisher=req.publisher, product_name=req.product_name, file_version=req.file_version
        )])
        if active:
            return {"ok": True, "duplicate": True, "request_id": active["id"], "status": active["status"]}

        if req.sha256:
            if req.requested_by:
                pending = conn.execute(
                    """SELECT id,status FROM approval_requests WHERE device_id=? AND sha256=? AND requested_by=?
                       AND status IN ('pending','approving') ORDER BY id DESC LIMIT 1""",
                    (device_id, req.sha256, req.requested_by),
                ).fetchone()
            else:
                pending = conn.execute(
                    """SELECT id,status FROM approval_requests WHERE device_id=? AND sha256=?
                       AND status IN ('pending','approving') ORDER BY id DESC LIMIT 1""",
                    (device_id, req.sha256),
                ).fetchone()
        else:
            if req.requested_by:
                pending = conn.execute(
                    """SELECT id,status FROM approval_requests WHERE device_id=? AND lower(file_path)=lower(?) AND requested_by=?
                       AND status IN ('pending','approving') ORDER BY id DESC LIMIT 1""",
                    (device_id, req.file_path, req.requested_by),
                ).fetchone()
            else:
                pending = conn.execute(
                    """SELECT id,status FROM approval_requests WHERE device_id=? AND lower(file_path)=lower(?)
                       AND status IN ('pending','approving') ORDER BY id DESC LIMIT 1""",
                    (device_id, req.file_path),
                ).fetchone()
        if pending:
            return {"ok": True, "duplicate": True, "request_id": pending["id"], "status": pending["status"]}

        cur = conn.execute(
            """INSERT INTO approval_requests(device_id,file_path,policy_source_path,sha256,publisher,product_name,file_version,reason,requested_by,status,created_at,component_count,request_kind)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                device_id, req.file_path, req.policy_source_path, req.sha256, req.publisher, req.product_name, req.file_version,
                req.reason, req.requested_by, "pending", utcnow(), 1, "file",
            ),
        )
        request_id = cur.lastrowid
        conn.execute(
            """INSERT OR IGNORE INTO approval_request_items
               (request_id,original_path,policy_source_path,sha256,publisher,product_name,file_version)
               VALUES(?,?,?,?,?,?,?)""",
            (request_id, req.file_path, req.policy_source_path, req.sha256, req.publisher, req.product_name, req.file_version),
        )
    return {"ok": True, "request_id": request_id, "status": "pending"}


@app.post("/api/requests/session")
def create_session_request(req: ApprovalSessionIn, device_id: str = Depends(agent_auth)):
    # De-duplicate the component list while preserving the first-seen order.
    unique: list[ApprovalComponentIn] = []
    seen: set[tuple[str, str]] = set()
    for component in req.components:
        path = (component.file_path or "").strip()
        if not path:
            continue
        key = ((component.sha256 or "").lower(), path.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(component)
    if not unique:
        raise HTTPException(status_code=400, detail="No blocked components were supplied")

    with db() as conn:
        if req.session_key:
            pending = conn.execute(
                """SELECT id,status FROM approval_requests WHERE device_id=? AND session_key=?
                   AND status IN ('pending','approving') ORDER BY id DESC LIMIT 1""",
                (device_id, req.session_key),
            ).fetchone()
            if pending:
                return {"ok": True, "duplicate": True, "request_id": pending["id"], "status": pending["status"]}

        active = find_active_overlapping_request(conn, device_id, req.requested_by, unique)
        if active:
            return {"ok": True, "duplicate": True, "request_id": active["id"], "status": active["status"]}

        for component in unique:
            blocked = find_existing_block(conn, device_id, component_as_approval(component))
            if blocked:
                return {
                    "ok": True, "blocked": True, "status": "blocked",
                    "policy_id": blocked["policy_id"],
                    "decision_note": blocked["note"] or "One or more components are explicitly blocked by an administrator.",
                }

        uncovered = [c for c in unique if not find_existing_approved(conn, device_id, component_as_approval(c))]
        if not uncovered:
            first = find_existing_approved(conn, device_id, component_as_approval(unique[0]))
            return {
                "ok": True, "already_approved": True,
                "request_id": first["request_id"] if first else None,
                "policy_id": first["policy_id"] if first else None,
                "rule_type": first["rule_type"] if first else None,
            }

        primary = unique[0]
        cur = conn.execute(
            """INSERT INTO approval_requests
               (device_id,file_path,policy_source_path,sha256,publisher,product_name,file_version,reason,requested_by,status,created_at,component_count,request_kind,session_key)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (device_id, primary.file_path, primary.policy_source_path, primary.sha256, primary.publisher, primary.product_name,
             primary.file_version, req.reason, req.requested_by, "pending", utcnow(), len(unique), "session", req.session_key),
        )
        request_id = cur.lastrowid
        for c in unique:
            conn.execute(
                """INSERT OR IGNORE INTO approval_request_items
                   (request_id,original_path,policy_source_path,sha256,publisher,product_name,file_version,parent_path,record_id)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (request_id,c.file_path,c.policy_source_path,c.sha256,c.publisher,c.product_name,c.file_version,c.parent_path,c.record_id),
            )
    return {"ok": True, "request_id": request_id, "status": "pending", "component_count": len(unique)}


@app.get("/api/requests")
def get_request_statuses(requested_by: Optional[str] = None, device_id: str = Depends(agent_auth)):
    with db() as conn:
        params = [device_id]
        where = "r.device_id=?"
        if requested_by:
            where += " AND (r.requested_by=? OR r.requested_by IS NULL OR r.requested_by='')"
            params.append(requested_by)
        rows = conn.execute(
            f"""SELECT r.*,a.policy_id,a.rule_type FROM approval_requests r
                LEFT JOIN approved_applications a ON a.request_id=r.id
                WHERE {where}
                ORDER BY r.id DESC LIMIT 50""",
            params,
        ).fetchall()
    result = []
    with db() as conn:
        for r in rows:
            items = conn.execute(
                "SELECT original_path,sha256,publisher,product_name,file_version,parent_path,record_id FROM approval_request_items WHERE request_id=? ORDER BY id",
                (r["id"],),
            ).fetchall()
            result.append({
                "id": r["id"], "file_path": r["file_path"], "sha256": r["sha256"],
                "publisher": r["publisher"], "product_name": r["product_name"],
                "file_version": r["file_version"], "reason": r["reason"],
                "requested_by": r["requested_by"], "status": r["status"],
                "created_at": r["created_at"], "decided_at": r["decided_at"],
                "decided_by": r["decided_by"], "decision_note": r["decision_note"],
                "policy_id": r["policy_id"], "rule_type": r["rule_type"],
                "component_count": r["component_count"] if "component_count" in r.keys() else 1,
                "components": [
                    {
                        "file_path": i["original_path"], "sha256": i["sha256"], "publisher": i["publisher"],
                        "product_name": i["product_name"], "file_version": i["file_version"],
                        "parent_path": i["parent_path"], "record_id": i["record_id"],
                    } for i in items
                ],
            })
    return result


@app.post('/api/offboard-complete')
def offboard_complete(req: OffboardComplete, device_id: str = Depends(agent_auth)):
    with db() as conn:
        d=conn.execute('SELECT organization_id,hostname FROM devices WHERE id=?',(device_id,)).fetchone()
        if not d:
            raise HTTPException(status_code=404,detail='Device not found')
        state='completed' if req.success else 'failed'
        conn.execute('UPDATE devices SET offboard_status=?,offboard_result=?,offboard_completed_at=? WHERE id=?',(state,req.result,utcnow() if req.success else None,device_id))
        audit(conn,'agent','device_offboard_completed' if req.success else 'device_offboard_failed',organization_id=d['organization_id'],device_id=device_id,object_type='device',object_id=device_id,detail=req.result or d['hostname'])
    return {'ok':True}


@app.get("/api/commands")
def get_commands(device_id: str = Depends(agent_auth)):
    # Claim exactly one validated command at a time. A fresh opaque claim is issued on
    # every dispatch so stale/replayed completions cannot commit a recovered command.
    with db() as conn:
        requeue_stale_commands(conn)
        while True:
            row = conn.execute(
                "SELECT * FROM commands WHERE device_id=? AND status='pending' ORDER BY id LIMIT 1",
                (device_id,),
            ).fetchone()
            if not row:
                return []
            validation_error=validate_agent_command(row['command_type'],row['payload'])
            if validation_error:
                fail_invalid_command(conn,row,validation_error)
                continue
            started = utcnow()
            claim_token=secrets.token_urlsafe(32)
            claim_hash=hash_key(claim_token)
            changed = conn.execute(
                """UPDATE commands SET status='processing',started_at=?,claim_token_hash=?,attempt_count=COALESCE(attempt_count,0)+1
                   WHERE id=? AND status='pending'""",
                (started, claim_hash, row["id"]),
            ).rowcount
            if not changed:
                continue
            row = conn.execute("SELECT * FROM commands WHERE id=?", (row["id"],)).fetchone()
            return [{
                "id": row["id"], "command_type": row["command_type"],
                "payload": json.loads(row["payload"]), "created_at": row["created_at"],
                "claim_token": claim_token
            }]


@app.post("/api/commands/{command_id}/complete")
def complete_command(command_id: int, req: CommandComplete, device_id: str = Depends(agent_auth)):
    with db() as conn:
        row = conn.execute("SELECT * FROM commands WHERE id=?", (command_id,)).fetchone()
        if not row or row["device_id"] != device_id:
            raise HTTPException(status_code=404, detail="Command not found")
        # Completed/failed results are idempotent; a retry after a successful POST is harmless.
        if row["status"] in {"completed","failed"}:
            return {"ok": True, "duplicate": True}
        device=conn.execute("SELECT agent_version FROM devices WHERE id=?",(device_id,)).fetchone()
        requires_claim=bool(device and version_at_least(device["agent_version"],"0.13.0"))
        stored_claim=row["claim_token_hash"] or ""
        supplied_claim=(req.claim_token or "").strip()
        if requires_claim or supplied_claim:
            if not supplied_claim or not stored_claim or not hmac.compare_digest(hash_key(supplied_claim),stored_claim):
                raise HTTPException(status_code=409, detail="Command claim is stale or invalid")
        if row["status"] != "processing":
            raise HTTPException(status_code=409, detail="Command is not currently claimed")
        status_value = "completed" if req.success else "failed"
        conn.execute(
            "UPDATE commands SET status=?,completed_at=?,result=?,claim_token_hash=NULL WHERE id=?",
            (status_value, utcnow(), req.result, command_id),
        )

        try:
            payload = json.loads(row["payload"] or "{}")
        except Exception:
            payload = {}

        if row["command_type"] == "update_agent":
            target_version=payload.get("target_version")
            release_id=payload.get("release_id")
            if req.success:
                conn.execute("UPDATE devices SET desired_agent_version=?,update_status='installing',update_result=? WHERE id=?",(target_version,req.result,device_id))
                conn.execute("UPDATE agent_update_history SET status='installing',detail=? WHERE command_id=?",(req.result,command_id))
            else:
                conn.execute("UPDATE devices SET update_status='failed',update_result=?,last_update_at=? WHERE id=?",(req.result,utcnow(),device_id))
                conn.execute("UPDATE agent_update_history SET status='failed',detail=?,completed_at=? WHERE command_id=?",(req.result,utcnow(),command_id))

        if row["command_type"] == "uninstall_agent":
            conn.execute('UPDATE devices SET offboard_status=?,offboard_result=? WHERE id=?',('uninstalling' if req.success else 'failed',req.result,device_id))

        if req.success and row["command_type"] == "return_to_learning":
            conn.execute(
                "UPDATE devices SET learning_mode=1,policy_mode='learning' WHERE id=?",
                (device_id,),
            )
        elif req.success and row["command_type"] == "enable_enforcement":
            conn.execute(
                "UPDATE devices SET learning_mode=0,policy_mode='enforcement' WHERE id=?",
                (device_id,),
            )

        if row["command_type"] == "revoke_approval":
            policy_id = (payload.get("policy_id") or "").upper()
            actor = payload.get("requested_by") or "administrator"
            if req.success and policy_id:
                request_ids = [r["request_id"] for r in conn.execute(
                    "SELECT DISTINCT request_id FROM approved_components WHERE device_id=? AND upper(policy_id)=upper(?) AND request_id IS NOT NULL",
                    (device_id, policy_id),
                ).fetchall()]
                conn.execute(
                    "UPDATE approved_components SET status='revoked',revoked_at=?,revoked_by=? WHERE device_id=? AND upper(policy_id)=upper(?)",
                    (utcnow(), actor, device_id, policy_id),
                )
                conn.execute(
                    "UPDATE approved_applications SET status='revoked',revoked_at=?,revoked_by=? WHERE device_id=? AND upper(policy_id)=upper(?)",
                    (utcnow(), actor, device_id, policy_id),
                )
                for rid in request_ids:
                    conn.execute(
                        "UPDATE approval_requests SET status='revoked',decision_note=? WHERE id=?",
                        (f"Approval policy revoked by {actor}. Other policies may still allow the application.", rid),
                    )
            elif not req.success and policy_id:
                conn.execute(
                    "UPDATE approved_components SET status='approved' WHERE device_id=? AND upper(policy_id)=upper(?) AND status='revoking'",
                    (device_id, policy_id),
                )
                conn.execute(
                    "UPDATE approved_applications SET status='approved' WHERE device_id=? AND upper(policy_id)=upper(?) AND status='revoking'",
                    (device_id, policy_id),
                )

        if row["command_type"] == "block_file":
            block_id = payload.get("block_id")
            if block_id:
                if req.success:
                    conn.execute(
                        """UPDATE blocked_applications SET status='blocked',policy_id=?,rule_type=?,blocked_at=?,note=? WHERE id=?""",
                        ((req.policy_id or '').upper(), req.rule_type or 'Generated deny policy', utcnow(), req.result, block_id),
                    )
                    block_row = conn.execute("SELECT * FROM blocked_applications WHERE id=?", (block_id,)).fetchone()
                    if block_row and block_row["source_component_id"]:
                        conn.execute("UPDATE approved_components SET status='blocked' WHERE id=?", (block_row["source_component_id"],))
                    if block_row and block_row['policy_definition_id']:
                        pdef = conn.execute("SELECT active FROM scoped_policies WHERE id=?", (block_row['policy_definition_id'],)).fetchone()
                        installed_policy_id = (req.policy_id or '').upper()
                        if pdef and not pdef['active'] and installed_policy_id:
                            conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",
                                         (device_id,'unblock_file',json.dumps({'block_id':block_id,'policy_id':installed_policy_id,'requested_by':'policy-engine'}),'pending',utcnow()))
                            conn.execute("UPDATE blocked_applications SET status='unblocking' WHERE id=?", (block_id,))
                else:
                    conn.execute("UPDATE blocked_applications SET status='failed',note=? WHERE id=?", (req.result, block_id))
                    block_row = conn.execute("SELECT source_component_id FROM blocked_applications WHERE id=?", (block_id,)).fetchone()
                    if block_row and block_row["source_component_id"]:
                        conn.execute("UPDATE approved_components SET status='approved' WHERE id=? AND status='blocking'", (block_row["source_component_id"],))

        if row["command_type"] == "unblock_file":
            block_id = payload.get("block_id")
            actor = payload.get("requested_by") or "administrator"
            if block_id:
                block_row = conn.execute("SELECT * FROM blocked_applications WHERE id=?", (block_id,)).fetchone()
                if req.success:
                    conn.execute(
                        "UPDATE blocked_applications SET status='unblocked',unblocked_at=?,unblocked_by=?,note=? WHERE id=?",
                        (utcnow(), actor, req.result, block_id),
                    )
                    if block_row and block_row["source_component_id"]:
                        conn.execute("UPDATE approved_components SET status='approved' WHERE id=? AND status='blocked'", (block_row["source_component_id"],))
                else:
                    conn.execute("UPDATE blocked_applications SET status='blocked',note=? WHERE id=?", (req.result, block_id))

        if row["command_type"] in {"approve_file", "approve_session"}:
            request_id = payload.get("request_id")
            if request_id:
                if req.success:
                    conn.execute(
                        "UPDATE approval_requests SET status='approved',decision_note=? WHERE id=?",
                        (req.result, request_id),
                    )
                    ar = conn.execute("SELECT * FROM approval_requests WHERE id=?", (request_id,)).fetchone()
                    items = conn.execute(
                        "SELECT * FROM approval_request_items WHERE request_id=? ORDER BY id", (request_id,)
                    ).fetchall()
                    if row["command_type"] == "approve_session":
                        commanded = {str(c.get("file_path", "")).lower() for c in payload.get("components", []) if c.get("file_path")}
                        items = [item for item in items if str(item["original_path"]).lower() in commanded]
                    if not items and ar:
                        items = [dict(
                            original_path=ar["file_path"], sha256=ar["sha256"], publisher=ar["publisher"],
                            product_name=ar["product_name"], file_version=ar["file_version"]
                        )]
                    policy_id = (req.policy_id or "").upper() or f"command-{command_id}"
                    rule_type = req.rule_type or "Generated policy"
                    scoped_policy_id = payload.get("scoped_policy_id")
                    for item in items:
                        file_path = item["original_path"]
                        sha256 = item["sha256"]
                        publisher = item["publisher"]
                        product_name = item["product_name"]
                        file_version = item["file_version"]
                        conn.execute(
                            """INSERT OR IGNORE INTO approved_components
                               (device_id,request_id,file_path,sha256,publisher,product_name,file_version,rule_type,policy_id,approved_at,policy_definition_id)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                            (device_id,request_id,file_path,sha256,publisher,product_name,file_version,rule_type,policy_id,utcnow(),scoped_policy_id),
                        )
                    # Preserve the legacy one-row-per-policy inventory using the request's primary item.
                    if ar:
                        conn.execute(
                            """INSERT OR REPLACE INTO approved_applications
                               (device_id,request_id,file_path,sha256,publisher,product_name,file_version,rule_type,policy_id,approved_at,policy_definition_id)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                            (device_id,request_id,ar["file_path"],ar["sha256"],ar["publisher"],ar["product_name"],
                             ar["file_version"],rule_type,policy_id,utcnow(),scoped_policy_id),
                        )
                else:
                    conn.execute(
                        "UPDATE approval_requests SET status='approval_failed',decision_note=? WHERE id=?",
                        (req.result, request_id),
                    )
    return {"ok": True}


def scope_options_for_device(conn: sqlite3.Connection, principal: Principal, device: sqlite3.Row) -> str:
    opts = ["<option value='device'>This device</option>"]
    if device['group_id']:
        group = conn.execute('SELECT name FROM device_groups WHERE id=?', (device['group_id'],)).fetchone()
        opts.append(f"<option value='group'>Group: {escape(group['name'] if group else str(device['group_id']))}</option>")
    opts.append("<option value='organization'>Entire organization</option>")
    if principal.can_manage_global:
        opts.append("<option value='global'>All organizations</option>")
    return ''.join(opts)


PAGE_SIZE = 50


def short_publisher(subject: Optional[str]) -> str:
    if not subject:
        return ''
    m = re.search(r'(?:^|,)\\s*CN=([^,]+)', subject, re.I)
    return m.group(1).strip() if m else subject.split(',')[0].strip()


def filename(path: Optional[str]) -> str:
    return ntpath.basename(path or '') or (path or '')


def display_time(value: Optional[str]) -> str:
    if not value:
        return ''
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M')
    except Exception:
        return value


REQUEST_STATUS_LABELS = {
    'pending': 'Pending',
    'approving': 'Approving',
    'approved': 'Approved',
    'approved_existing': 'Approved (existing policy)',
    'denied': 'Denied',
    'blocked': 'Blocked',
    'failed': 'Failed',
    'approval_failed': 'Failed',
    'revoked': 'Revoked',
}


def request_status_label(value: Optional[str]) -> str:
    status=(value or '').strip().lower()
    return REQUEST_STATUS_LABELS.get(status, status.replace('_',' ').title() or 'Unknown')


def request_status_class(value: Optional[str]) -> str:
    status=(value or '').strip().lower()
    if status in {'approved','approved_existing'}:
        return 'badge-ok'
    if status in {'pending','approving'}:
        return 'badge-warn'
    if status in {'denied','blocked','failed','approval_failed','revoked'}:
        return 'badge-bad'
    return ''


BLOCK_STATUS_LABELS = {
    'blocking': 'Blocking',
    'blocked': 'Blocked',
    'unblocking': 'Unblocking',
    'unblocked': 'Unblocked',
    'failed': 'Failed',
}


def block_status_label(value: Optional[str]) -> str:
    status=(value or '').strip().lower()
    return BLOCK_STATUS_LABELS.get(status, status.replace('_',' ').title() or 'Unknown')


def block_status_class(value: Optional[str]) -> str:
    status=(value or '').strip().lower()
    if status=='blocked':
        return 'badge-bad'
    if status in {'blocking','unblocking'}:
        return 'badge-warn'
    if status=='unblocked':
        return 'badge-ok'
    if status=='failed':
        return 'badge-bad'
    return ''


def related_block_for_event(conn: sqlite3.Connection, event: sqlite3.Row):
    path=(event['file_path'] or '').strip()
    if not path:
        return None
    when=event['occurred_at'] or event['received_at'] or utcnow()
    return conn.execute(
        """SELECT b.*,p.scope_type,p.scope_id,p.active scoped_active
           FROM blocked_applications b LEFT JOIN scoped_policies p ON p.id=b.policy_definition_id
           WHERE b.device_id=? AND lower(b.file_path)=lower(?) AND b.created_at<=?
             AND (b.unblocked_at IS NULL OR b.unblocked_at>=?) AND b.status<>'failed'
           ORDER BY b.id DESC LIMIT 1""",
        (event['device_id'],path,when,when),
    ).fetchone()


def related_request_for_event(conn: sqlite3.Connection, event: sqlite3.Row):
    path=(event['file_path'] or '').strip()
    sha=(event['sha256'] or '').strip()
    when=event['occurred_at'] or event['received_at'] or utcnow()
    if not path and not sha:
        return None
    return conn.execute(
        """SELECT * FROM approval_requests
           WHERE device_id=?
             AND ((?<>'' AND sha256=?) OR (?<>'' AND lower(file_path)=lower(?)))
             AND ABS(julianday(created_at)-julianday(?))<=7
           ORDER BY ABS(julianday(created_at)-julianday(?)) ASC,id DESC LIMIT 1""",
        (event['device_id'],sha,sha,path,path,when,when),
    ).fetchone()


def elapsed_label(start: Optional[str], end: Optional[str] = None) -> str:
    if not start:
        return ''
    try:
        start_dt=datetime.fromisoformat(start.replace('Z','+00:00'))
        end_dt=datetime.fromisoformat(end.replace('Z','+00:00')) if end else datetime.now(timezone.utc)
        if start_dt.tzinfo is None:
            start_dt=start_dt.replace(tzinfo=timezone.utc)
        if end_dt.tzinfo is None:
            end_dt=end_dt.replace(tzinfo=timezone.utc)
        seconds=max(0,int((end_dt-start_dt).total_seconds()))
        if seconds < 60:
            return '<1 min'
        minutes=seconds//60
        if minutes < 60:
            return f'{minutes} min'
        hours=minutes//60
        if hours < 48:
            return f'{hours} hr' if hours==1 else f'{hours} hrs'
        days=hours//24
        return f'{days} day' if days==1 else f'{days} days'
    except Exception:
        return ''


def clipped(value: Optional[str], limit: int = 150) -> str:
    text=(value or '').strip()
    return text if len(text)<=limit else text[:max(1,limit-1)].rstrip()+'…'


def app_cell(product: Optional[str], path: Optional[str], detail_url: Optional[str] = None) -> str:
    fn = filename(path)
    name = product or fn or 'Unknown application'
    title = f"<b>{escape(name)}</b>"
    if detail_url:
        title = f"<a href='{detail_url}'>{title}</a>"
    sub = '' if fn == name else f"<div class='file-sub' title='{escape(path or fn)}'>{escape(fn)}</div>"
    return f"<div class='app-cell'>{title}{sub}</div>"


def pager(path: str, page_num: int, total: int, params: dict, page_size: int = PAGE_SIZE) -> str:
    pages = max(1, (total + page_size - 1) // page_size)
    page_num = min(max(page_num, 1), pages)
    start = 0 if total == 0 else (page_num - 1) * page_size + 1
    end = min(total, page_num * page_size)
    def link(label: str, target: int) -> str:
        q = dict(params)
        q['page'] = target
        return f"<a href='{path}?{escape(urlencode(q))}'><button type='button'>{escape(label)}</button></a>"
    prev = link('Previous', page_num - 1) if page_num > 1 else ''
    nxt = link('Next', page_num + 1) if page_num < pages else ''
    return f"<div class='pagination'><div class='muted'>Showing {start}-{end} of {total}</div><div class='pages'>{prev}<span class='badge'>Page {page_num} of {pages}</span>{nxt}</div></div>"



def _report_period(period: int) -> tuple[int, str, str]:
    period = period if period in {7, 30, 90, 365} else 30
    cutoff = (datetime.now(timezone.utc) - timedelta(days=period)).isoformat()
    return period, cutoff, f'Last {period} days'


def _report_scope(conn: sqlite3.Connection, principal: Principal, organization_id: str = '', device_id: str = '', alias: str = 'd') -> tuple[str, list[object], str]:
    clause, params = visible_device_clause(principal, alias)
    where=[clause]; args=list(params); label='All visible devices'
    if principal.can_manage_global and organization_id:
        org=conn.execute('SELECT name FROM organizations WHERE id=?',(int(organization_id),)).fetchone()
        if org:
            where.append(f'{alias}.organization_id=?'); args.append(int(organization_id)); label=f"Organization: {org['name']}"
    if device_id:
        dev=conn.execute(f'SELECT hostname,organization_id FROM devices {alias} WHERE {alias}.id=?',(device_id,)).fetchone()
        if dev and principal_can_see_org(principal,dev['organization_id']):
            where.append(f'{alias}.id=?'); args.append(device_id); label=f"Device: {dev['hostname']}"
    return ' AND '.join(where), args, label


def _report_filter_html(conn: sqlite3.Connection, principal: Principal, report_type: str, period: int, organization_id: str, device_id: str) -> str:
    if principal.can_manage_global:
        orgs=conn.execute("SELECT id,name FROM organizations WHERE status='active' ORDER BY name").fetchall()
    else:
        orgs=conn.execute('SELECT id,name FROM organizations WHERE id=?',(principal.organization_id,)).fetchall()
    clause,params=visible_device_clause(principal,'d')
    devs=conn.execute(f"SELECT d.id,d.hostname,d.organization_id FROM devices d WHERE {clause} ORDER BY d.hostname",params).fetchall()
    period_opts=''.join(f"<option value='{v}' {'selected' if period==v else ''}>Last {v} days</option>" for v in (7,30,90,365))
    period_html='' if report_type in {'device-compliance','policies','agent-updates'} else f"<div class='field'><label>Period</label><select name='period'>{period_opts}</select></div>"
    org_html=''
    if principal.can_manage_global:
        org_opts="<option value=''>All organizations</option>"+''.join(f"<option value='{o['id']}' {'selected' if organization_id==str(o['id']) else ''}>{escape(o['name'])}</option>" for o in orgs)
        org_html=f"<div class='field'><label>Organization</label><select name='organization_id'>{org_opts}</select></div>"
    dev_opts="<option value=''>All devices</option>"+''.join(f"<option value='{escape(d['id'])}' {'selected' if device_id==d['id'] else ''}>{escape(d['hostname'])}</option>" for d in devs if not organization_id or str(d['organization_id'])==organization_id)
    return f"<form class='filters no-print' method='get' action='/reports/{escape(report_type)}'>{period_html}{org_html}<div class='field'><label>Device</label><select name='device_id'>{dev_opts}</select></div><button class='btn-primary'>Run Report</button><a href='/reports/{escape(report_type)}'><button type='button'>Reset</button></a></form>"


def _csv_response(filename_value: str, sections: list[tuple[str,list[str],list[list[object]]]], summary: list[tuple[str,object]] | None = None) -> Response:
    out=io.StringIO(newline='')
    w=csv.writer(out)
    if summary:
        w.writerow(['Summary'])
        for k,v in summary: w.writerow([k,v])
        w.writerow([])
    for heading,columns,rows in sections:
        w.writerow([heading])
        w.writerow(columns)
        for row in rows: w.writerow(row)
        w.writerow([])
    data='\ufeff'+out.getvalue()
    return Response(content=data,media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="{filename_value}"'})


def _report_table(title: str, columns: list[str], rows: list[list[object]], max_rows: int = 250) -> str:
    shown=rows[:max_rows]
    hdr=''.join(f'<th>{escape(c)}</th>' for c in columns)
    body=''.join('<tr>'+''.join(f'<td>{escape(str(v if v is not None else ""))}</td>' for v in row)+'</tr>' for row in shown)
    if not body: body=f"<tr><td colspan='{len(columns)}'><div class=empty>No data for this report period.</div></td></tr>"
    note=f"<p class='muted'>Showing first {max_rows} of {len(rows)} rows in the browser. CSV export includes all rows.</p>" if len(rows)>max_rows else ''
    return f"<div class='section-head'><h2>{escape(title)}</h2></div><div class='card'><table><thead><tr>{hdr}</tr></thead><tbody>{body}</tbody></table></div>{note}"


def _report_metric_cards(metrics: list[tuple[str,object,str]]) -> str:
    return "<div class='grid'>"+''.join(f"<div class='stat'><span class='stat-label'>{escape(label)}</span><b>{escape(str(value))}</b><span class='trend'>{escape(note)}</span></div>" for label,value,note in metrics)+"</div>"


def build_report(conn: sqlite3.Connection, principal: Principal, report_type: str, period: int = 30, organization_id: str = '', device_id: str = '') -> dict:
    period,cutoff,period_label=_report_period(period)
    scope,args,scope_label=_report_scope(conn,principal,organization_id,device_id,'d')
    now=datetime.now(timezone.utc); online_cutoff=(now-timedelta(minutes=10)).isoformat()
    common={'period':period,'cutoff':cutoff,'period_label':period_label,'scope_label':scope_label}
    if report_type=='executive':
        total=conn.execute(f'SELECT COUNT(*) n FROM devices d WHERE {scope}',args).fetchone()['n']
        online=conn.execute(f'SELECT COUNT(*) n FROM devices d WHERE {scope} AND d.last_seen>=?',args+[online_cutoff]).fetchone()['n']
        enforcement=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {scope} AND lower(COALESCE(NULLIF(d.policy_mode,'unknown'),CASE WHEN d.learning_mode=1 THEN 'learning' ELSE 'enforcement' END))='enforcement'",args).fetchone()['n']
        pending=conn.execute(f"SELECT COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {scope} AND r.status='pending'",args).fetchone()['n']
        blocks=conn.execute(f"SELECT COUNT(*) n FROM events e JOIN devices d ON d.id=e.device_id WHERE {scope} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=?",args+[cutoff]).fetchone()['n']
        requests=conn.execute(f"SELECT COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {scope} AND r.created_at>=?",args+[cutoff]).fetchone()['n']
        approvals=conn.execute(f"SELECT COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {scope} AND r.decided_at>=? AND r.status IN ('approved','approved_existing')",args+[cutoff]).fetchone()['n']
        denied=conn.execute(f"SELECT COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {scope} AND r.decided_at>=? AND r.status IN ('denied','blocked')",args+[cutoff]).fetchone()['n']
        attention=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {scope} AND d.desired_agent_version IS NOT NULL AND COALESCE(d.agent_version,'')<>d.desired_agent_version",args).fetchone()['n']
        top=conn.execute(f"""SELECT COALESCE(NULLIF(e.product_name,''),e.file_path) application,COUNT(*) blocks,COUNT(DISTINCT e.device_id) devices,MAX(COALESCE(e.occurred_at,e.received_at)) last_seen
            FROM events e JOIN devices d ON d.id=e.device_id WHERE {scope} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=?
            GROUP BY COALESCE(NULLIF(e.product_name,''),e.file_path) ORDER BY blocks DESC LIMIT 15""",args+[cutoff]).fetchall()
        top_rows=[[r['application'],r['blocks'],r['devices'],display_time(r['last_seen'])] for r in top]
        versions=conn.execute(f"SELECT COALESCE(NULLIF(d.agent_version,''),'Unknown') version,COUNT(*) n FROM devices d WHERE {scope} GROUP BY COALESCE(NULLIF(d.agent_version,''),'Unknown') ORDER BY n DESC",args).fetchall()
        ver_rows=[[r['version'],r['n']] for r in versions]
        metrics=[('Managed devices',total,f'{online} online now'),('Enforcement coverage',f"{round(enforcement*100/total) if total else 0}%",f'{enforcement} of {total} devices'),('Blocked events',blocks,period_label),('Approval requests',requests,f'{approvals} approved / {denied} denied'),('Pending approvals',pending,'Administrator action required'),('Pending updates',attention,'Devices not yet at desired version')]
        sections=[('Top Blocked Applications',['Application','Blocked Events','Devices','Last Seen'],top_rows),('Agent Version Distribution',['Agent Version','Devices'],ver_rows)]
        summary=[('Period',period_label),('Scope',scope_label),('Managed devices',total),('Online devices',online),('Enforcement devices',enforcement),('Blocked events',blocks),('Approval requests',requests),('Approved requests',approvals),('Denied requests',denied),('Pending approvals',pending),('Devices pending update',attention)]
        return dict(common,title='Executive Summary',description='High-level application-control posture, approvals, blocks, enforcement coverage and agent health.',metrics=metrics,sections=sections,summary=summary)
    if report_type=='application-activity':
        block_rows=conn.execute(f"""SELECT COALESCE(NULLIF(e.product_name,''),e.file_path) application,COALESCE(e.publisher,'') publisher,COUNT(*) blocks,COUNT(DISTINCT e.device_id) devices,MIN(COALESCE(e.occurred_at,e.received_at)) first_seen,MAX(COALESCE(e.occurred_at,e.received_at)) last_seen FROM events e JOIN devices d ON d.id=e.device_id WHERE {scope} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=? GROUP BY COALESCE(NULLIF(e.product_name,''),e.file_path),COALESCE(e.publisher,'') ORDER BY blocks DESC""",args+[cutoff]).fetchall()
        blocked_rows=[[r['application'],short_publisher(r['publisher']),r['blocks'],r['devices'],display_time(r['first_seen']),display_time(r['last_seen'])] for r in block_rows]
        observed_rows_db=conn.execute(f"""SELECT COALESCE(NULLIF(e.product_name,''),e.file_path) application,COALESCE(e.publisher,'') publisher,COUNT(*) observations,COUNT(DISTINCT e.device_id) devices,MAX(COALESCE(e.occurred_at,e.received_at)) last_seen FROM events e JOIN devices d ON d.id=e.device_id WHERE {scope} AND COALESCE(e.occurred_at,e.received_at)>=? GROUP BY COALESCE(NULLIF(e.product_name,''),e.file_path),COALESCE(e.publisher,'') ORDER BY observations DESC LIMIT 250""",args+[cutoff]).fetchall()
        observed_rows=[[r['application'],short_publisher(r['publisher']),r['observations'],r['devices'],display_time(r['last_seen'])] for r in observed_rows_db]
        observed=conn.execute(f"SELECT COUNT(*) n FROM events e JOIN devices d ON d.id=e.device_id WHERE {scope} AND COALESCE(e.occurred_at,e.received_at)>=?",args+[cutoff]).fetchone()['n']; unique=conn.execute(f"SELECT COUNT(DISTINCT COALESCE(NULLIF(e.product_name,''),e.file_path)) n FROM events e JOIN devices d ON d.id=e.device_id WHERE {scope} AND COALESCE(e.occurred_at,e.received_at)>=?",args+[cutoff]).fetchone()['n']; blocks=sum(r['blocks'] for r in block_rows); affected=conn.execute(f"SELECT COUNT(DISTINCT e.device_id) n FROM events e JOIN devices d ON d.id=e.device_id WHERE {scope} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=?",args+[cutoff]).fetchone()['n']
        metrics=[('Observed events',observed,period_label),('Unique applications',unique,'Distinct product/path identities'),('Blocked events',blocks,'Windows App Control event 3077'),('Affected devices',affected,'Devices with at least one block')]
        return dict(common,title='Application Control Activity',description='Application observations and block activity across the selected scope.',metrics=metrics,sections=[('Top Observed Applications',['Application','Publisher','Observations','Devices','Last Seen'],observed_rows),('Blocked Application Activity',['Application','Publisher','Blocks','Devices','First Seen','Last Seen'],blocked_rows)],summary=[('Period',period_label),('Scope',scope_label),('Observed events',observed),('Unique applications',unique),('Blocked events',blocks),('Affected devices',affected)])
    if report_type=='device-compliance':
        devices=conn.execute(f"""SELECT d.*,o.name organization_name,g.name group_name FROM devices d LEFT JOIN organizations o ON o.id=d.organization_id LEFT JOIN device_groups g ON g.id=d.group_id WHERE {scope} ORDER BY d.hostname""",args).fetchall()
        rows=[]; enforcement=online=current=0
        for d in devices:
            mode=display_mode(d); enforcement += 1 if mode=='Enforcement' else 0
            is_online=bool(d['last_seen'] and d['last_seen']>=online_cutoff); online += 1 if is_online else 0
            up_to_date=not d['desired_agent_version'] or d['agent_version']==d['desired_agent_version']; current += 1 if up_to_date else 0
            rows.append([d['hostname'],d['organization_name'] or '',d['group_name'] or '',mode,d['agent_version'] or '',d['desired_agent_version'] or '',d['update_status'] or ('current' if up_to_date else ''),'Online' if is_online else 'Offline',display_time(d['last_seen']) or 'Never',d['offboard_status'] or ''])
        total=len(devices)
        metrics=[('Devices',total,scope_label),('Enforcement',f'{round(enforcement*100/total) if total else 0}%',f'{enforcement} devices'),('Online now',f'{round(online*100/total) if total else 0}%',f'{online} devices'),('Agent compliant',f'{round(current*100/total) if total else 0}%',f'{current} at desired version')]
        return dict(common,period_label='Current state',title='Device Compliance',description='Endpoint enforcement mode, connectivity, agent version and update compliance.',metrics=metrics,sections=[('Device Compliance',['Device','Organization','Group','Mode','Agent','Desired Agent','Update Status','Connectivity','Last Seen','Offboarding'],rows)],summary=[('Scope',scope_label),('Devices',total),('Enforcement devices',enforcement),('Online devices',online),('Agent-compliant devices',current)])
    if report_type=='approvals':
        rs=conn.execute(f"""SELECT r.*,d.hostname,o.name organization_name FROM approval_requests r JOIN devices d ON d.id=r.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND r.created_at>=? ORDER BY r.id DESC""",args+[cutoff]).fetchall()
        rows=[[r['id'],r['product_name'] or filename(r['file_path']),r['hostname'],r['organization_name'] or '',r['requested_by'] or '',request_status_label(r['status']),r['decided_by'] or '',display_time(r['created_at']),display_time(r['decided_at']),r['reason'] or '',r['decision_note'] or ''] for r in rs]
        counts={st:sum(1 for r in rs if r['status']==st) for st in {'pending','approving','approved','approved_existing','denied','blocked','failed','approval_failed','revoked'}}
        failed_count=counts.get('failed',0)+counts.get('approval_failed',0)
        metrics=[('Requests',len(rs),period_label),('Approved',counts.get('approved',0)+counts.get('approved_existing',0),'Completed approvals'),('Denied / blocked',counts.get('denied',0)+counts.get('blocked',0),'Rejected or explicitly blocked'),('Pending / approving',counts.get('pending',0)+counts.get('approving',0),'Awaiting/finalizing decision'),('Failed',failed_count,'Approval operations requiring review')]
        return dict(common,title='Approval Decisions',description='Request history, decision outcomes, users and administrators involved.',metrics=metrics,sections=[('Approval Request History',['ID','Application','Device','Organization','Requested By','Status','Decided By','Requested','Decided','Request Reason','Decision Message'],rows)],summary=[('Period',period_label),('Scope',scope_label),('Requests',len(rs)),('Approved',counts.get('approved',0)+counts.get('approved_existing',0)),('Denied',counts.get('denied',0)),('Blocked',counts.get('blocked',0)),('Pending',counts.get('pending',0)),('Failed',failed_count)])
    if report_type=='operations':
        offline_cutoff=(now-timedelta(days=OFFLINE_ATTENTION_DAYS)).isoformat()
        stalled_cutoff=(now-timedelta(minutes=30)).isoformat()
        pending_rs=conn.execute(f"""SELECT r.*,d.hostname,o.name organization_name FROM approval_requests r JOIN devices d ON d.id=r.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND r.status='pending' ORDER BY r.created_at ASC""",args).fetchall()
        pending_rows=[[r['id'],r['product_name'] or filename(r['file_path']),r['hostname'],r['organization_name'] or '',r['requested_by'] or '',display_time(r['created_at']),elapsed_label(r['created_at']),r['reason'] or ''] for r in pending_rs]
        failed_req=conn.execute(f"""SELECT r.*,d.hostname,o.name organization_name FROM approval_requests r JOIN devices d ON d.id=r.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND r.status IN ('failed','approval_failed') AND r.created_at>=? ORDER BY r.id DESC""",args+[cutoff]).fetchall()
        failed_req_rows=[[r['id'],r['product_name'] or filename(r['file_path']),r['hostname'],r['organization_name'] or '',display_time(r['created_at']),r['decision_note'] or ''] for r in failed_req]
        failed_cmd=conn.execute(f"""SELECT c.*,d.hostname,o.name organization_name FROM commands c JOIN devices d ON d.id=c.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND c.status='failed' AND c.created_at>=? ORDER BY c.id DESC""",args+[cutoff]).fetchall()
        stalled_cmd=conn.execute(f"""SELECT c.*,d.hostname,o.name organization_name FROM commands c JOIN devices d ON d.id=c.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND c.status IN ('pending','processing') AND c.created_at<? ORDER BY c.created_at ASC""",args+[stalled_cutoff]).fetchall()
        command_rows=[[c['id'],c['hostname'],c['organization_name'] or '',c['command_type'],request_status_label('failed') if c['status']=='failed' else c['status'].title(),display_time(c['created_at']),elapsed_label(c['created_at']),c['result'] or ''] for c in list(failed_cmd)+list(stalled_cmd)]
        devices=conn.execute(f"""SELECT d.*,o.name organization_name FROM devices d LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} ORDER BY d.hostname""",args).fetchall()
        device_rows=[]; update_attention=offline_attention=update_failed=0
        for d in devices:
            reasons=[]
            desired=d['desired_agent_version'] or ''; current=d['agent_version'] or ''; update_status=(d['update_status'] or '').lower()
            if desired and desired!=current:
                update_attention += 1
                if update_status in {'failed','rolled_back'}: update_failed += 1
                reasons.append(f"Agent {current or 'unknown'} → {desired} ({update_status or 'pending'})")
            last=d['last_seen'] or d['created_at']
            offboard=(d['offboard_status'] or '').lower()
            if offboard not in {'queued','uninstalling','completed'} and last and last<offline_cutoff:
                offline_attention += 1
                reasons.append(f"Offline {elapsed_label(last)}")
            if reasons:
                device_rows.append([d['hostname'],d['organization_name'] or '',display_mode(d),current,desired,display_time(d['last_seen']) or 'Never','; '.join(reasons),d['update_result'] or ''])
        block_failures=conn.execute(f"""SELECT b.*,d.hostname,o.name organization_name FROM blocked_applications b JOIN devices d ON d.id=b.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND b.status='failed' ORDER BY b.id DESC""",args).fetchall()
        block_rows=[[b['id'],b['product_name'] or filename(b['file_path']),b['hostname'],b['organization_name'] or '',display_time(b['created_at']),b['blocked_by'] or '',b['note'] or ''] for b in block_failures]
        command_count=len(failed_cmd)+len(stalled_cmd)
        metrics=[('Pending approvals',len(pending_rs),'Awaiting administrator decision'),('Approval failures',len(failed_req),period_label),('Command issues',command_count,f'{len(failed_cmd)} failed · {len(stalled_cmd)} stalled 30+ min'),('Devices needing update',update_attention,f'{update_failed} failed / rolled back'),('Offline devices',offline_attention,f'{OFFLINE_ATTENTION_DAYS}+ days'),('Block failures',len(block_failures),'Explicit deny operations requiring review')]
        sections=[('Pending Approval Queue',['ID','Application','Device','Organization','Requested By','Requested','Open For','Reason'],pending_rows),('Approval Failures',['ID','Application','Device','Organization','Requested','Failure Detail'],failed_req_rows),('Command Issues',['ID','Device','Organization','Command','Status','Created','Age','Result'],command_rows),('Devices Needing Attention',['Device','Organization','Mode','Agent','Desired Agent','Last Seen','Reason','Update Result'],device_rows),('Explicit Block Failures',['ID','Application','Device','Organization','Created','Initiated By','Failure Detail'],block_rows)]
        summary=[('Period for recent failures',period_label),('Scope',scope_label),('Pending approvals',len(pending_rs)),('Approval failures',len(failed_req)),('Failed commands',len(failed_cmd)),('Stalled commands',len(stalled_cmd)),('Devices needing update',update_attention),('Failed/rolled-back updates',update_failed),('Offline devices',offline_attention),('Block failures',len(block_failures))]
        return dict(common,title='Operations Review',description='Action-oriented view of pending decisions, failed or stalled endpoint work, update issues, offline devices and explicit-block failures.',metrics=metrics,sections=sections,summary=summary)
    if report_type=='policies':
        if principal.can_manage_global and not organization_id and not device_id:
            prs=conn.execute("SELECT * FROM scoped_policies WHERE deleted_at IS NULL ORDER BY active DESC,action,id DESC").fetchall()
        else:
            # Show policies effective within the selected visible organization/device scope.
            org_id=int(organization_id) if organization_id else principal.organization_id
            if device_id:
                dev=conn.execute('SELECT organization_id,group_id FROM devices WHERE id=?',(device_id,)).fetchone(); org_id=dev['organization_id'] if dev else org_id
                prs=conn.execute("SELECT * FROM scoped_policies WHERE deleted_at IS NULL AND (scope_type='global' OR organization_id=? OR (scope_type='device' AND scope_id=?)) ORDER BY active DESC,action,id DESC",(org_id,device_id)).fetchall()
            else:
                prs=conn.execute("SELECT * FROM scoped_policies WHERE deleted_at IS NULL AND (scope_type='global' OR organization_id=?) ORDER BY active DESC,action,id DESC",(org_id,)).fetchall()
        rows=[]
        for r in prs:
            rows.append([r['id'],r['name'],r['action'].upper(),policy_scope_label(conn,r),r['identity_type'],short_publisher(r['publisher']),r['product_name'] or '',r['rule_type'] or '', 'Active' if r['active'] else 'Disabled',r['created_by'] or '',display_time(r['created_at'])])
        active=sum(1 for r in prs if r['active']); blocks=sum(1 for r in prs if r['active'] and r['action']=='block'); allows=sum(1 for r in prs if r['active'] and r['action']=='allow')
        metrics=[('Policies',len(prs),scope_label),('Active policies',active,'Currently enforced/eligible'),('Active ALLOW',allows,'Application allow policies'),('Active BLOCK',blocks,'Explicit deny policies')]
        return dict(common,period_label='Current state',title='Policy Inventory',description='Central ALLOW/BLOCK policy inventory, scope, identity and status.',metrics=metrics,sections=[('Application Policies',['ID','Name','Action','Scope','Identity','Publisher','Product','Rule Type','Status','Created By','Created'],rows)],summary=[('Scope',scope_label),('Policies',len(prs)),('Active',active),('ALLOW',allows),('BLOCK',blocks)])
    if report_type=='agent-updates':
        ds=conn.execute(f"SELECT d.*,o.name organization_name FROM devices d LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} ORDER BY d.hostname",args).fetchall()
        rows=[]; pending=failed=current=0
        for d in ds:
            status=(d['update_status'] or '').lower(); desired=d['desired_agent_version'] or ''
            is_current=not desired or desired==d['agent_version']
            current += 1 if is_current else 0; failed += 1 if status in {'failed','rolled_back'} else 0; pending += 1 if not is_current and status not in {'failed','rolled_back'} else 0
            rows.append([d['hostname'],d['organization_name'] or '',d['agent_version'] or '',desired,status or ('current' if is_current else 'pending'),display_time(d['last_update_at']),d['update_result'] or ''])
        metrics=[('Devices',len(ds),scope_label),('Current',current,'At desired agent version'),('Pending update',pending,'Queued/installing/not yet current'),('Failed / rolled back',failed,'Requires attention')]
        return dict(common,period_label='Current state',title='Agent Update Compliance',description='Current and desired agent versions plus managed-update outcome.',metrics=metrics,sections=[('Agent Update Status',['Device','Organization','Current Version','Desired Version','Status','Last Update','Result'],rows)],summary=[('Scope',scope_label),('Devices',len(ds)),('Current',current),('Pending',pending),('Failed/Rolled Back',failed)])
    if report_type=='blocked-events':
        rs=conn.execute(f"""SELECT e.*,d.hostname,o.name organization_name FROM events e JOIN devices d ON d.id=e.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=? ORDER BY e.id DESC""",args+[cutoff]).fetchall()
        rows=[]; explicit=0; with_request=0
        for r in rs:
            block_row=related_block_for_event(conn,r); request_row=related_request_for_event(conn,r)
            reason='Explicit block' if block_row else 'Not allowed by policy'
            explicit += 1 if block_row else 0
            with_request += 1 if request_row else 0
            rows.append([display_time(r['occurred_at'] or r['received_at']),r['hostname'],r['organization_name'] or '',r['product_name'] or filename(r['file_path']),r['file_path'] or '',short_publisher(r['publisher']),r['file_version'] or '',reason,block_row['id'] if block_row else '',request_row['id'] if request_row else '',request_status_label(request_row['status']) if request_row else '',request_row['decision_note'] if request_row else '',r['parent_path'] or '',r['sha256'] or '',r['record_id'] or ''])
        unique=len({(r['product_name'] or '',r['file_path'] or '') for r in rs}); devices=len({r['device_id'] for r in rs})
        metrics=[('Blocked events',len(rs),period_label),('Explicit blocks',explicit,'Matched AppControl Manager deny records'),('Policy blocks',len(rs)-explicit,'Not allowed by current policy'),('Affected devices',devices,'Devices with block activity')]
        return dict(common,title='Blocked Event Detail',description='Correlated Windows App Control block telemetry with explicit block and approval-request context.',metrics=metrics,sections=[('Blocked Events',['Time','Device','Organization','Application','Full Path','Publisher','Version','Reason','Explicit Block ID','Related Request ID','Request Status','Decision Message','Parent Process','SHA256','CI Record ID'],rows)],summary=[('Period',period_label),('Scope',scope_label),('Blocked events',len(rs)),('Explicit blocks',explicit),('Policy blocks',len(rs)-explicit),('Events with related request',with_request),('Unique applications',unique),('Affected devices',devices)])
    if report_type=='commands':
        rs=conn.execute(f"""SELECT c.*,d.hostname,o.name organization_name FROM commands c JOIN devices d ON d.id=c.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {scope} AND c.created_at>=? ORDER BY c.id DESC""",args+[cutoff]).fetchall()
        rows=[[c['id'],c['hostname'],c['organization_name'] or '',c['command_type'],c['status'],c['attempt_count'] or 0,display_time(c['created_at']),display_time(c['started_at']),display_time(c['completed_at']),c['result'] or ''] for c in rs]
        failed=sum(1 for c in rs if c['status']=='failed'); processing=sum(1 for c in rs if c['status'] in {'pending','processing'})
        metrics=[('Commands',len(rs),period_label),('Pending / processing',processing,'Endpoint work still active'),('Failed',failed,'Commands requiring review')]
        return dict(common,title='Command History',description='Endpoint command execution history including policy, update and lifecycle operations.',metrics=metrics,sections=[('Endpoint Commands',['ID','Device','Organization','Command','Status','Attempts','Created','Started','Completed','Result'],rows)],summary=[('Period',period_label),('Scope',scope_label),('Commands',len(rs)),('Pending/Processing',processing),('Failed',failed)])
    if report_type=='audit':
        if principal.can_manage_global and not organization_id:
            where='a.occurred_at>=?'; aargs=[cutoff]
        else:
            oid=int(organization_id) if organization_id else principal.organization_id
            where='a.occurred_at>=? AND a.organization_id=?'; aargs=[cutoff,oid]
        if device_id:
            where += ' AND (a.device_id=? OR a.device_id IS NULL)'; aargs.append(device_id)
        ars=conn.execute(f"SELECT a.*,o.name organization_name FROM audit_log a LEFT JOIN organizations o ON o.id=a.organization_id WHERE {where} ORDER BY a.id DESC",aargs).fetchall()
        rows=[[display_time(r['occurred_at']),r['actor'] or '',r['action'],r['organization_name'] or '',r['device_id'] or '',r['object_type'] or '',r['object_id'] or '',r['detail'] or ''] for r in ars]
        actors=len({r['actor'] for r in ars if r['actor']}); actions=len({r['action'] for r in ars})
        metrics=[('Audit events',len(ars),period_label),('Actors',actors,'Distinct administrative/user actors'),('Action types',actions,'Distinct audited actions')]
        return dict(common,title='Administrative Audit',description='Administrative and security-sensitive changes recorded by AppControl Manager.',metrics=metrics,sections=[('Audit Activity',['Time','Actor','Action','Organization','Device','Object Type','Object ID','Detail'],rows)],summary=[('Period',period_label),('Scope',scope_label),('Audit events',len(ars)),('Actors',actors)])
    raise HTTPException(status_code=404,detail='Unknown report type')


def report_actions(report_type: str, period: int, organization_id: str, device_id: str) -> str:
    params={'period':period}
    if organization_id: params['organization_id']=organization_id
    if device_id: params['device_id']=device_id
    qs=urlencode(params)
    return f"<a class='button' href='/reports/{escape(report_type)}.csv?{escape(qs)}'>Download CSV</a><button class='btn-primary' type='button' onclick='window.print()'>Print / Save PDF</button>"


def render_report(report: dict, filter_html: str, actions: str) -> str:
    meta=f"{escape(report['period_label'])} · {escape(report['scope_label'])} · Generated {escape(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}"
    html=f"<div class='report-header print-only'><div class='kicker'>AppControl Manager Report</div><div class='report-title'>{escape(report['title'])}</div><div class='report-meta'>{meta}</div></div>{filter_html}{_report_metric_cards(report['metrics'])}"
    for heading,columns,rows in report['sections']:
        html += _report_table(heading,columns,rows)
    return html


def request_actions(conn: sqlite3.Connection, principal: Principal, r: sqlite3.Row) -> str:
    if r['status'] != 'pending':
        note=(r['decision_note'] or '').strip()
        return f"<span class='muted'>{escape(note)}</span>" if note else ''
    if not principal.can_approve:
        return ''
    d = conn.execute('SELECT * FROM devices WHERE id=?', (r['device_id'],)).fetchone()
    if not d:
        return ''
    opts = scope_options_for_device(conn, principal, d)
    return (f"<div class='table-actions'><form class='actions' method='post' action='/admin/requests/{r['id']}/approve'><select class='scope-select' name='scope_type'>{opts}</select><button class='btn-primary'>Approve</button></form>"
            f"<form class='actions' method='post' action='/admin/requests/{r['id']}/block'><select class='scope-select' name='scope_type'>{opts}</select><button class='btn-danger'>Block</button></form>"
            f"<a class='button btn-warning' href='/requests/{r['id']}/deny'>Deny request</a></div>")



@app.get('/search', response_class=HTMLResponse)
def global_search(q:str='', principal:Principal=Depends(admin_auth)):
    q=(q or '').strip()
    if len(q)<2:
        return page('Search',"<div class='panel'><p>Enter at least two characters in the search box to find devices, applications and policies.</p></div>",principal,subtitle='Search across the management console.')
    term=f"%{q.lower()}%"
    with db() as conn:
        clause,args=visible_device_clause(principal,'d')
        devices=conn.execute(f"""SELECT d.id,d.hostname,d.os_version,d.agent_version,o.name organization_name FROM devices d LEFT JOIN organizations o ON o.id=d.organization_id WHERE {clause} AND (lower(d.hostname) LIKE ? OR lower(COALESCE(d.os_version,'')) LIKE ? OR lower(COALESCE(d.agent_version,'')) LIKE ?) ORDER BY d.hostname LIMIT 25""",args+[term,term,term]).fetchall()
        apps=conn.execute(f"""SELECT e.id,e.device_id,d.hostname,e.product_name,e.file_path,e.publisher,MAX(COALESCE(e.occurred_at,e.received_at)) last_seen,COUNT(*) occurrences FROM events e JOIN devices d ON d.id=e.device_id WHERE {clause} AND (lower(COALESCE(e.product_name,'')) LIKE ? OR lower(COALESCE(e.file_path,'')) LIKE ? OR lower(COALESCE(e.publisher,'')) LIKE ?) GROUP BY e.device_id,COALESCE(NULLIF(e.product_name,''),e.file_path) ORDER BY last_seen DESC LIMIT 40""",args+[term,term,term]).fetchall()
        if principal.can_manage_global:
            policies=conn.execute("SELECT * FROM scoped_policies WHERE deleted_at IS NULL AND (lower(name) LIKE ? OR lower(COALESCE(product_name,'')) LIKE ? OR lower(COALESCE(publisher,'')) LIKE ? OR lower(COALESCE(file_path,'')) LIKE ?) ORDER BY active DESC,id DESC LIMIT 25",(term,term,term,term)).fetchall()
        else:
            policies=conn.execute("SELECT * FROM scoped_policies WHERE deleted_at IS NULL AND (scope_type='global' OR organization_id=?) AND (lower(name) LIKE ? OR lower(COALESCE(product_name,'')) LIKE ? OR lower(COALESCE(publisher,'')) LIKE ? OR lower(COALESCE(file_path,'')) LIKE ?) ORDER BY active DESC,id DESC LIMIT 25",(principal.organization_id,term,term,term,term)).fetchall()
        policy_views=[(p,policy_scope_label(conn,p)) for p in policies]
    drows=''.join(f"<tr><td><a href='/devices/{d['id']}'><b>{escape(d['hostname'])}</b></a></td><td>{escape(d['organization_name'] or '')}</td><td>{escape(d['agent_version'] or '')}</td><td>{escape(d['os_version'] or '')}</td></tr>" for d in devices)
    arows=''.join(f"<tr><td>{app_cell(a['product_name'],a['file_path'],'/events/%s' % a['id'])}</td><td><a href='/devices/{a['device_id']}'>{escape(a['hostname'])}</a></td><td>{escape(short_publisher(a['publisher']))}</td><td>{a['occurrences']}</td><td>{display_time(a['last_seen'])}</td></tr>" for a in apps)
    prows=''.join(f"<tr><td><a href='/policies'><b>{escape(p['name'])}</b></a></td><td><span class='badge {'badge-bad' if p['action']=='block' else 'badge-ok'}'>{escape(p['action'].upper())}</span></td><td>{escape(scope_label)}</td><td>{escape(p['product_name'] or filename(p['file_path']))}</td><td>{'Active' if p['active'] else 'Disabled'}</td></tr>" for p,scope_label in policy_views)
    body=f"<div class='notice-info'>Results for <b>{escape(q)}</b></div><div class='section-head'><h2>Devices</h2><span class='muted'>{len(devices)} result(s)</span></div><div class='card'><table><tr><th>Device</th><th>Organization</th><th>Agent</th><th>OS</th></tr>{drows or '<tr><td colspan=4>No matching devices.</td></tr>'}</table></div><div class='section-head'><h2>Applications / Events</h2><span class='muted'>{len(apps)} result(s)</span></div><div class='card'><table><tr><th>Application</th><th>Device</th><th>Publisher</th><th>Occurrences</th><th>Last Seen</th></tr>{arows or '<tr><td colspan=5>No matching applications.</td></tr>'}</table></div><div class='section-head'><h2>Policies</h2><span class='muted'>{len(policies)} result(s)</span></div><div class='card'><table><tr><th>Policy</th><th>Action</th><th>Scope</th><th>Application</th><th>Status</th></tr>{prows or '<tr><td colspan=5>No matching policies.</td></tr>'}</table></div>"
    return page('Search',body,principal,subtitle='Search across devices, observed applications and policy inventory.')


@app.get('/reports', response_class=HTMLResponse)
def reports_center(principal:Principal=Depends(admin_auth)):
    cards=[
        ('executive','▥','Executive Summary','Security posture, enforcement coverage, approvals, blocks and agent health.'),
        ('operations','⚠','Operations Review','Pending decisions, failures, stalled endpoint work, update issues and offline devices requiring attention.'),
        ('application-activity','◉','Application Control Activity','Top observed and blocked applications, publishers, affected devices and activity trends.'),
        ('blocked-events','×','Blocked Event Detail','Correlated block telemetry with explicit deny, approval-request, path, publisher and process context.'),
        ('device-compliance','▣','Device Compliance','Enforcement mode, online state, agent version and update compliance by endpoint.'),
        ('approvals','!','Approval Decisions','Request volumes, outcomes, requestors, approvers and decision history.'),
        ('policies','▤','Policy Inventory','Central ALLOW/BLOCK policies, scope, identity, creator and status.'),
        ('agent-updates','⇧','Agent Update Compliance','Current vs. desired agent versions, pending updates and failures.'),
        ('commands','↻','Command History','Endpoint policy, update and lifecycle command execution results.'),
        ('audit','≡','Administrative Audit','Security-sensitive administrative and user actions for review and evidence.'),
    ]
    html=''.join(f"<a class='report-card' href='/reports/{slug}'><div class='report-icon'>{icon}</div><h3>{escape(title)}</h3><p>{escape(desc)}</p></a>" for slug,icon,title,desc in cards)
    body=f"<div class='notice-info'><b>Reporting:</b> reports can be filtered by period, organization and device, exported to CSV, or printed/saved as PDF directly from the browser.</div><div class='report-grid'>{html}</div>"
    return page('Reports',body,principal,subtitle='Operational, security and compliance reporting for AppControl Manager.')


@app.get('/reports/{report_type}.csv')
def report_csv(report_type:str,period:int=30,organization_id:str='',device_id:str='',principal:Principal=Depends(admin_auth)):
    with db() as conn:
        report=build_report(conn,principal,report_type,period,organization_id,device_id)
    safe=re.sub(r'[^a-z0-9-]+','-',report_type.lower()).strip('-')
    return _csv_response(f'appcontrol-manager-{safe}-{datetime.now(timezone.utc).strftime("%Y%m%d")}.csv',report['sections'],report['summary'])


@app.get('/reports/{report_type}', response_class=HTMLResponse)
def report_page(report_type:str,period:int=30,organization_id:str='',device_id:str='',principal:Principal=Depends(admin_auth)):
    with db() as conn:
        report=build_report(conn,principal,report_type,period,organization_id,device_id)
        filters=_report_filter_html(conn,principal,report_type,report['period'],organization_id,device_id)
    actions=report_actions(report_type,report['period'],organization_id,device_id)
    return page(report['title'],render_report(report,filters,actions),principal,subtitle=report['description'],actions=actions)


@app.get("/", response_class=HTMLResponse)
def dashboard(busy: int = 0, principal: Principal = Depends(admin_auth)):
    with db() as conn:
        clause,params=visible_device_clause(principal,'d'); now=datetime.now(timezone.utc)
        online_cutoff=(now-timedelta(minutes=10)).isoformat(); day_cutoff=(now-timedelta(hours=24)).isoformat(); week_cutoff=(now-timedelta(days=7)).isoformat()
        device_count=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {clause}",params).fetchone()['n']
        online_count=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {clause} AND d.last_seen>=?",params+[online_cutoff]).fetchone()['n']
        enforcement_count=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {clause} AND lower(COALESCE(NULLIF(d.policy_mode,'unknown'),CASE WHEN d.learning_mode=1 THEN 'learning' ELSE 'enforcement' END))='enforcement'",params).fetchone()['n']
        pending_count=conn.execute(f"SELECT COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {clause} AND r.status='pending'",params).fetchone()['n']
        blocks_24h=conn.execute(f"SELECT COUNT(*) n FROM events e JOIN devices d ON d.id=e.device_id WHERE {clause} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=?",params+[day_cutoff]).fetchone()['n']
        blocks_7d=conn.execute(f"SELECT COUNT(*) n FROM events e JOIN devices d ON d.id=e.device_id WHERE {clause} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=?",params+[week_cutoff]).fetchone()['n']
        update_attention=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {clause} AND d.desired_agent_version IS NOT NULL AND COALESCE(d.agent_version,'')<>d.desired_agent_version",params).fetchone()['n']
        approval_failures=conn.execute(f"SELECT COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {clause} AND r.status IN ('failed','approval_failed') AND r.created_at>=?",params+[week_cutoff]).fetchone()['n']
        failed_commands=conn.execute(f"SELECT COUNT(*) n FROM commands c JOIN devices d ON d.id=c.device_id WHERE {clause} AND c.status='failed' AND c.created_at>=?",params+[week_cutoff]).fetchone()['n']
        block_failures=conn.execute(f"SELECT COUNT(*) n FROM blocked_applications b JOIN devices d ON d.id=b.device_id WHERE {clause} AND b.status='failed'",params).fetchone()['n']
        update_failures=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {clause} AND d.desired_agent_version IS NOT NULL AND COALESCE(d.agent_version,'')<>d.desired_agent_version AND lower(COALESCE(d.update_status,'')) IN ('failed','rolled_back')",params).fetchone()['n']
        offline_attention_cutoff=(now-timedelta(days=OFFLINE_ATTENTION_DAYS)).isoformat()
        offline_attention=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {clause} AND COALESCE(d.offboard_status,'') NOT IN ('queued','uninstalling','completed') AND COALESCE(d.last_seen,d.created_at)<?",params+[offline_attention_cutoff]).fetchone()['n']
        operations_issues=approval_failures+failed_commands+block_failures+update_failures+offline_attention
        if principal.can_manage_global:
            allow_count=conn.execute("SELECT COUNT(*) n FROM scoped_policies WHERE active=1 AND deleted_at IS NULL AND action='allow'").fetchone()['n']; block_count=conn.execute("SELECT COUNT(*) n FROM scoped_policies WHERE active=1 AND deleted_at IS NULL AND action='block'").fetchone()['n']
        else:
            allow_count=conn.execute("SELECT COUNT(*) n FROM scoped_policies WHERE active=1 AND deleted_at IS NULL AND action='allow' AND (scope_type='global' OR organization_id=?)",(principal.organization_id,)).fetchone()['n']; block_count=conn.execute("SELECT COUNT(*) n FROM scoped_policies WHERE active=1 AND deleted_at IS NULL AND action='block' AND (scope_type='global' OR organization_id=?)",(principal.organization_id,)).fetchone()['n']
        pending=conn.execute(f"""SELECT r.*,d.hostname,d.organization_id,d.group_id,o.name organization_name FROM approval_requests r JOIN devices d ON d.id=r.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {clause} AND r.status='pending' ORDER BY r.id DESC LIMIT 8""",params).fetchall()
        attention_cutoff=(now-timedelta(days=OFFLINE_ATTENTION_DAYS)).isoformat()
        attention=conn.execute(f"""SELECT d.*,o.name organization_name,g.name group_name FROM devices d LEFT JOIN organizations o ON o.id=d.organization_id LEFT JOIN device_groups g ON g.id=d.group_id WHERE {clause} AND COALESCE(d.offboard_status,'') NOT IN ('queued','uninstalling','completed') AND ((d.desired_agent_version IS NOT NULL AND COALESCE(d.agent_version,'')<>d.desired_agent_version AND COALESCE(d.update_status,'') IN ('queued','installing','installed','failed','rolled_back','bootstrap_required','downloading','staging')) OR COALESCE(d.last_seen,d.created_at)<?) ORDER BY CASE WHEN d.desired_agent_version IS NOT NULL AND COALESCE(d.agent_version,'')<>d.desired_agent_version THEN 0 ELSE 1 END,COALESCE(d.last_seen,d.created_at) ASC LIMIT 8""",params+[attention_cutoff]).fetchall()
        recent_blocks=conn.execute(f"""SELECT e.id,e.device_id,e.product_name,e.file_path,e.occurred_at,e.received_at,d.hostname FROM events e JOIN devices d ON d.id=e.device_id WHERE {clause} AND e.event_id=3077 ORDER BY e.id DESC LIMIT 6""",params).fetchall()
        recent_decisions=conn.execute(f"""SELECT r.id,r.device_id,r.product_name,r.file_path,r.status,r.decided_by,r.decided_at,r.decision_note,d.hostname FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {clause} AND r.status NOT IN ('pending','approving') ORDER BY COALESCE(r.decided_at,r.created_at) DESC,r.id DESC LIMIT 6""",params).fetchall()
        versions=conn.execute(f"SELECT COALESCE(NULLIF(d.agent_version,''),'Unknown') version,COUNT(*) n FROM devices d WHERE {clause} GROUP BY COALESCE(NULLIF(d.agent_version,''),'Unknown') ORDER BY n DESC LIMIT 8",params).fetchall()
        daily=[]
        for ago in range(6,-1,-1):
            start=(now-timedelta(days=ago)).replace(hour=0,minute=0,second=0,microsecond=0); finish=start+timedelta(days=1)
            n=conn.execute(f"SELECT COUNT(*) n FROM events e JOIN devices d ON d.id=e.device_id WHERE {clause} AND e.event_id=3077 AND COALESCE(e.occurred_at,e.received_at)>=? AND COALESCE(e.occurred_at,e.received_at)<?",params+[start.isoformat(),finish.isoformat()]).fetchone()['n']
            daily.append((start.strftime('%a'),n))
        req_rows=[]
        for r in pending:
            actions=request_actions(conn,principal,r); count=r['component_count'] or 1; related=f" <span class='muted'>(+{count-1} related)</span>" if count>1 else ''
            req_rows.append(f"<tr><td>{app_cell(r['product_name'],r['file_path'],'/requests/%s' % r['id'])}{related}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a></td><td>{escape(r['requested_by'] or '')}</td><td class='nowrap'>{display_time(r['created_at'])}</td><td><span class='clip'>{escape(r['reason'] or '')}</span></td><td>{actions}</td></tr>")
    notice="<div class='notice'><b>Device policy operation already in progress.</b> Wait for the current endpoint command to complete.</div>" if busy else ''
    attention_parts=[]
    for d in attention:
        update_pending=bool(d['desired_agent_version'] and (d['agent_version'] or '')!=d['desired_agent_version'])
        if update_pending: reason=f"Agent {d['agent_version'] or 'unknown'} → {d['desired_agent_version']} · {(d['update_status'] or 'pending').replace('_',' ')}"
        else: reason=f"Offline {OFFLINE_ATTENTION_DAYS}+ days"
        badge='badge-bad' if (d['update_status'] or '').lower() in {'failed','rolled_back'} else 'badge-warn'
        attention_parts.append(f"<tr><td><a href='/devices/{d['id']}'><b>{escape(d['hostname'])}</b></a></td><td>{escape(d['organization_name'] or '')}</td><td><span class='badge {badge}'>{escape(reason)}</span></td><td>{display_time(d['last_seen']) or 'Never'}</td></tr>")
    recent_rows=''.join(f"<tr><td class='nowrap'>{display_time(r['occurred_at'] or r['received_at'])}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a></td><td>{app_cell(r['product_name'],r['file_path'],'/events/%s' % r['id'])}</td></tr>" for r in recent_blocks)
    decision_rows=''.join(f"<tr><td class='nowrap'>{display_time(r['decided_at'])}</td><td>{app_cell(r['product_name'],r['file_path'],'/requests/%s' % r['id'])}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a></td><td><span class='badge {request_status_class(r['status'])}'>{escape(request_status_label(r['status']))}</span></td><td>{escape(r['decided_by'] or 'System')}<div class='muted' title='{escape(r['decision_note'] or '')}'>{escape(clipped(r['decision_note'] or '',90))}</div></td></tr>" for r in recent_decisions)
    max_daily=max([n for _,n in daily] or [1]) or 1
    bars=''.join(f"<div class='spark-bar-wrap' title='{n} blocked events'><div class='spark-bar' style='height:{max(3,round(n*78/max_daily))}px'></div><div class='spark-label'>{escape(day)}</div></div>" for day,n in daily)
    max_ver=max([r['n'] for r in versions] or [1]) or 1
    verbars=''.join(f"<div class='bar-row'><span class='clip'>{escape(r['version'])}</span><div class='bar-track'><div class='bar-fill' style='width:{round(r['n']*100/max_ver)}%'></div></div><b>{r['n']}</b></div>" for r in versions)
    enforcement_pct=round(enforcement_count*100/device_count) if device_count else 0; online_pct=round(online_count*100/device_count) if device_count else 0
    policy_total=allow_count+block_count
    body=f"""{notice}<div class='grid'>
      <div class='stat'><span class='stat-label'>Managed Devices</span><b>{device_count}</b><span class='trend'>{online_count} online now</span></div>
      <div class='stat'><span class='stat-label'>Pending Approvals</span><b>{pending_count}</b><span class='trend'>Administrator action required</span></div>
      <div class='stat'><span class='stat-label'>Blocked Events / 24h</span><b>{blocks_24h}</b><span class='trend'>{blocks_7d} during the last 7 days</span></div>
      <div class='stat'><span class='stat-label'>Devices Pending Update</span><b>{update_attention}</b><span class='trend'>Not yet at desired agent version</span></div>
      <div class='stat'><span class='stat-label'>Active Policies</span><b>{policy_total}</b><span class='trend'>{allow_count} allow · {block_count} block</span></div>
      <div class='stat'><span class='stat-label'>Items Needing Review</span><b>{operations_issues}</b><span class='trend'>{approval_failures} approval · {failed_commands} command · {block_failures} block · {update_failures} update · {offline_attention} offline</span></div>
    </div>
    <div class='section-head'><h2>Pending Approval Requests</h2><a href='/requests'>View all requests →</a></div>
    <div class='card'><table><tr><th>Application</th><th>Device</th><th>Requested By</th><th>Requested</th><th>Reason</th><th>Action / Scope</th></tr>{''.join(req_rows) or '<tr><td colspan=6><div class="empty">No pending approval requests.</div></td></tr>'}</table></div>
    <div class='grid-2'>
      <div><div class='section-head'><h2>Operational Health</h2><a href='/reports/device-compliance'>Compliance report →</a></div><div class='panel'>
        <div class='metric-row'><span>Enforcement coverage</span><span class='metric-value'>{enforcement_pct}%</span></div><div class='progress success'><span style='width:{enforcement_pct}%'></span></div>
        <div class='metric-row'><span>Online in last 10 minutes</span><span class='metric-value'>{online_pct}%</span></div><div class='progress'><span style='width:{online_pct}%'></span></div>
        <div class='metric-row'><span>Devices needing update</span><span class='metric-value'>{update_attention}</span></div>
        <div class='metric-row'><span>Pending approval queue</span><span class='metric-value'>{pending_count}</span></div>
      </div></div>
      <div><div class='section-head'><h2>Blocked Activity · 7 Days</h2><a href='/reports/application-activity?period=7'>Activity report →</a></div><div class='panel'><div class='spark-bars'>{bars}</div><div class='muted' style='text-align:center'>{blocks_7d} total blocked events</div></div></div>
    </div>
    <div class='grid-2'>
      <div><div class='section-head'><h2>Devices Needing Attention</h2><a href='/devices'>View devices →</a></div><div class='card'><table><tr><th>Device</th><th>Organization</th><th>Reason</th><th>Last Seen</th></tr>{''.join(attention_parts) or '<tr><td colspan=4><div class="empty">No devices currently need attention.</div></td></tr>'}</table></div></div>
      <div><div class='section-head'><h2>Agent Version Distribution</h2><a href='/reports/agent-updates'>Update report →</a></div><div class='panel'><div class='bar-list'>{verbars or '<div class="empty">No agent version data.</div>'}</div></div></div>
    </div>
    <div class='grid-2'>
      <div><div class='section-head'><h2>Recent Approval Decisions</h2><a href='/requests?sort=newest'>View request history →</a></div><div class='card'><table><tr><th>Time</th><th>Application</th><th>Device</th><th>Status</th><th>Decision</th></tr>{decision_rows or '<tr><td colspan=5><div class="empty">No completed decisions.</div></td></tr>'}</table></div></div>
      <div><div class='section-head'><h2>Recent Blocked Events</h2><a href='/blocked-events'>View all activity →</a></div><div class='card'><table><tr><th>Time</th><th>Device</th><th>Application</th></tr>{recent_rows or '<tr><td colspan=3><div class="empty">No blocked events.</div></td></tr>'}</table></div></div>
    </div>"""
    return page('Dashboard',body,principal,subtitle='Operational overview of application control, endpoint health and pending work.',actions="<a class='button' href='/reports/operations'>Operations Review</a><a class='button' href='/reports/executive'>Executive Report</a>")


@app.get('/devices', response_class=HTMLResponse)
def devices_page(q:str='',organization_id:str='',group_id:str='',mode:str='',stale:int=0,bulk_result:str='',page_num:int=Query(1,alias='page'),principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    with db() as conn:
        clause,params=visible_device_clause(principal,'d'); where=[clause]; args=list(params)
        if q:
            where.append("(lower(d.hostname) LIKE ? OR lower(COALESCE(d.os_version,'')) LIKE ? OR lower(COALESCE(d.agent_version,'')) LIKE ?)"); term=f"%{q.lower()}%"; args += [term,term,term]
        if principal.can_manage_global and organization_id: where.append('d.organization_id=?'); args.append(int(organization_id))
        if group_id: where.append('d.group_id=?'); args.append(int(group_id))
        if mode in {'learning','enforcement'}:
            where.append("lower(COALESCE(NULLIF(d.policy_mode,'unknown'),CASE WHEN d.learning_mode=1 THEN 'learning' ELSE 'enforcement' END))=?"); args.append(mode)
        if stale:
            stale_cutoff=(datetime.now(timezone.utc)-timedelta(days=STALE_DEVICE_DAYS)).isoformat(); where.append('COALESCE(d.last_seen,d.created_at)<?'); args.append(stale_cutoff)
        where_sql=' AND '.join(where)
        total=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {where_sql}",args).fetchone()['n']
        rows=conn.execute(f"""SELECT d.*,o.name organization_name,g.name group_name FROM devices d LEFT JOIN organizations o ON o.id=d.organization_id LEFT JOIN device_groups g ON g.id=d.group_id WHERE {where_sql} ORDER BY d.hostname LIMIT ? OFFSET ?""",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
        # Summary counts reflect the full visible inventory, not only the current filter/page.
        base_clause,base_params=visible_device_clause(principal,'d'); cutoff=(datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat()
        all_total=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {base_clause}",base_params).fetchone()['n']
        all_online=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {base_clause} AND d.last_seen>=?",base_params+[cutoff]).fetchone()['n']
        all_enforcement=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {base_clause} AND lower(COALESCE(NULLIF(d.policy_mode,'unknown'),CASE WHEN d.learning_mode=1 THEN 'learning' ELSE 'enforcement' END))='enforcement'",base_params).fetchone()['n']
        all_updates=conn.execute(f"SELECT COUNT(*) n FROM devices d WHERE {base_clause} AND d.desired_agent_version IS NOT NULL AND COALESCE(d.agent_version,'')<>d.desired_agent_version",base_params).fetchone()['n']
        if principal.can_manage_global:
            orgs=conn.execute("SELECT id,name FROM organizations WHERE status='active' ORDER BY name").fetchall(); groups=conn.execute("SELECT id,name,organization_id FROM device_groups ORDER BY name").fetchall()
        else:
            orgs=conn.execute("SELECT id,name FROM organizations WHERE id=?",(principal.organization_id,)).fetchall(); groups=conn.execute("SELECT id,name,organization_id FROM device_groups WHERE organization_id=? ORDER BY name",(principal.organization_id,)).fetchall()
    html=[]
    for d in rows:
        online=bool(d['last_seen'] and d['last_seen']>=cutoff); offboard=(d['offboard_status'] or '').lower()
        if offboard=='completed': status_html="<span class='badge'>Offboarded</span>"
        elif offboard in {'queued','uninstalling'}: status_html="<span class='badge badge-warn'>Offboarding</span>"
        else: status_html="<span class='badge badge-ok'>Online</span>" if online else "<span class='badge badge-warn'>Offline</span>"
        update_html='';
        if d['desired_agent_version'] and (d['agent_version'] or '')!=d['desired_agent_version']:
            cls='badge-bad' if (d['update_status'] or '').lower() in {'failed','rolled_back'} else 'badge-warn'; update_html=f"<div><span class='badge {cls}'>{escape((d['update_status'] or 'Pending update').replace('_',' ').title())}</span></div>"
        can_delete,_=device_record_can_be_deleted(d); action=f"<a href='/devices/{d['id']}'><button type='button'>Open</button></a>"
        if can_delete and principal.can_manage_org: action += f"<form style='display:inline-block;margin-left:6px' method='post' action='/admin/devices/{d['id']}/delete' onsubmit=\"return confirm('Permanently delete the stale server record and stored history for {escape(d['hostname'])}?');\"><button class='btn-danger'>Delete</button></form>"
        select=f"<input type='checkbox' name='device_ids' value='{escape(d['id'])}'>" if principal.can_manage_org else ''
        html.append(f"<tr><td>{select}</td><td><a href='/devices/{d['id']}'><b>{escape(d['hostname'])}</b></a><div class='muted'>{escape(d['os_version'] or '')}</div></td><td>{escape(d['organization_name'] or '')}<div class='muted'>{escape(d['group_name'] or 'No group')}</div></td><td><span class='badge'>{escape(display_mode(d))}</span></td><td>{escape(d['agent_version'] or '')}{update_html}</td><td>{status_html}</td><td>{display_time(d['last_seen']) or 'Never'}</td><td>{action}</td></tr>")
    org_options="<option value=''>All organizations</option>"+''.join(f"<option value='{o['id']}' {'selected' if organization_id==str(o['id']) else ''}>{escape(o['name'])}</option>" for o in orgs) if principal.can_manage_global else ''
    group_options="<option value=''>All groups</option>"+''.join(f"<option value='{g['id']}' {'selected' if group_id==str(g['id']) else ''}>{escape(g['name'])}</option>" for g in groups)
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Device, OS, agent'></div>"+(f"<div class='field'><label>Organization</label><select name='organization_id'>{org_options}</select></div>" if principal.can_manage_global else '')+f"<div class='field'><label>Group</label><select name='group_id'>{group_options}</select></div><div class='field'><label>Mode</label><select name='mode'><option value=''>All modes</option><option value='learning' {'selected' if mode=='learning' else ''}>Learning</option><option value='enforcement' {'selected' if mode=='enforcement' else ''}>Enforcement</option></select></div><div class='field'><label>Inventory</label><select name='stale'><option value='0'>All devices</option><option value='1' {'selected' if stale else ''}>Stale ({STALE_DEVICE_DAYS}+ days)</option></select></div><button class='btn-primary'>Filter</button><a href='/devices'><button type='button'>Clear</button></a></form>"
    bulk=''
    if principal.can_manage_org:
        bulk_groups="<option value=''>No group</option>"+''.join(f"<option value='{g['id']}'>{escape(g['name'])}</option>" for g in groups)
        bulk=f"<div class='panel no-print'><div class='actions'><b>Bulk device actions</b><select name='bulk_action'><option value=''>Choose action…</option><option value='enforcement'>Enable Enforcement</option><option value='learning'>Return to Learning</option><option value='group'>Assign Device Group</option></select><select name='bulk_group_id'>{bulk_groups}</select><button class='btn-primary'>Apply to Selected</button><span class='muted'>Mode changes skip devices that already have an active endpoint command.</span></div></div>"
    notice=f"<div class='notice-info'>{escape(bulk_result)}</div>" if bulk_result else ''
    table=f"<div class='card'><table><tr><th style='width:35px'>Select</th><th>Device</th><th>Organization / Group</th><th>Mode</th><th>Agent</th><th>Status</th><th>Last Seen</th><th></th></tr>{''.join(html) or '<tr><td colspan=9><div class=\"empty\">No devices match these filters.</div></td></tr>'}</table></div>"
    if principal.can_manage_org: table=f"<form method='post' action='/admin/devices/bulk'>{bulk}{table}</form>"
    params_nav={'q':q,'organization_id':organization_id,'group_id':group_id,'mode':mode,'stale':stale}
    summary=f"<div class='grid'><div class='stat'><span class='stat-label'>Managed Devices</span><b>{all_total}</b></div><div class='stat'><span class='stat-label'>Online Now</span><b>{all_online}</b></div><div class='stat'><span class='stat-label'>Enforcement</span><b>{all_enforcement}</b></div><div class='stat'><span class='stat-label'>Pending Update</span><b>{all_updates}</b></div></div>"
    body=f"{notice}{summary}<div class='section-head'><h2>Device Inventory</h2><span class='muted'>{total} match current filters</span></div>{filters}{table}{pager('/devices',page_num,total,params_nav)}"
    return page('Devices',body,principal,subtitle='Search, filter and manage endpoint inventory. Select devices for bulk mode or group changes.',actions="<a class='button' href='/reports/device-compliance'>Compliance Report</a><a class='button' href='/reports/device-compliance.csv'>Export CSV</a>")


@app.get('/requests', response_class=HTMLResponse)
def requests_page(q:str='', request_status:str='', organization_id:str='', request_kind:str='', period:int=0,
                  sort:str='queue', page_num:int=Query(1,alias='page'), principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    period=period if period in {0,7,30,90,365} else 0
    request_kind=request_kind if request_kind in {'','file','session'} else ''
    sort=sort if sort in {'queue','newest','oldest'} else 'queue'
    valid_statuses=set(REQUEST_STATUS_LABELS)
    if request_status not in valid_statuses:
        request_status=''
    with db() as conn:
        clause,params=visible_device_clause(principal,'d')
        base_where=[clause]; base_args=list(params)
        if principal.can_manage_global and organization_id:
            try:
                org_id=int(organization_id)
            except ValueError:
                org_id=None
            if org_id is not None:
                base_where.append('d.organization_id=?'); base_args.append(org_id)
            else:
                organization_id=''
        if request_kind:
            base_where.append("COALESCE(r.request_kind,'file')=?"); base_args.append(request_kind)
        if period:
            cutoff=(datetime.now(timezone.utc)-timedelta(days=period)).isoformat()
            base_where.append('r.created_at>=?'); base_args.append(cutoff)
        if q:
            term=f"%{q.lower()}%"
            base_where.append("(lower(COALESCE(r.product_name,'')) LIKE ? OR lower(r.file_path) LIKE ? OR lower(COALESCE(r.publisher,'')) LIKE ? OR lower(d.hostname) LIKE ? OR lower(COALESCE(r.requested_by,'')) LIKE ? OR lower(COALESCE(r.decision_note,'')) LIKE ? OR lower(COALESCE(r.decided_by,'')) LIKE ?)")
            base_args += [term]*7
        base_sql=' AND '.join(base_where)
        status_rows=conn.execute(f"SELECT r.status,COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {base_sql} GROUP BY r.status",base_args).fetchall()
        counts={r['status']:r['n'] for r in status_rows}
        where=list(base_where); args=list(base_args)
        if request_status:
            if request_status=='failed':
                where.append("r.status IN ('failed','approval_failed')")
            else:
                where.append('r.status=?'); args.append(request_status)
        where_sql=' AND '.join(where)
        total=conn.execute(f"SELECT COUNT(*) n FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE {where_sql}",args).fetchone()['n']
        order_sql={
            'queue':"CASE r.status WHEN 'pending' THEN 0 WHEN 'approving' THEN 1 ELSE 2 END, r.id DESC",
            'newest':'r.id DESC',
            'oldest':'r.id ASC',
        }[sort]
        rows=conn.execute(f"""SELECT r.*,d.hostname,d.organization_id,d.group_id,o.name organization_name FROM approval_requests r
            JOIN devices d ON d.id=r.device_id LEFT JOIN organizations o ON o.id=d.organization_id
            WHERE {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?""",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
        orgs=conn.execute('SELECT id,name FROM organizations WHERE status=\'active\' ORDER BY name').fetchall() if principal.can_manage_global else []
        rendered=[]
        for r in rows:
            status_label=request_status_label(r['status']); cls=request_status_class(r['status'])
            component_count=int(r['component_count'] or 1) if 'component_count' in r.keys() else 1
            kind_label='Application session' if (r['request_kind'] or 'file')=='session' else 'File request'
            app_extra=f"<div class='muted'>{escape(short_publisher(r['publisher']))}</div>" if r['publisher'] else ''
            if component_count>1:
                app_extra += f"<div class='muted'>{component_count} components · {escape(kind_label)}</div>"
            timing=elapsed_label(r['created_at'],r['decided_at'] if r['status'] not in {'pending','approving'} else None)
            timing_label=('Open ' if r['status'] in {'pending','approving'} else 'Decision in ')+timing if timing else ''
            requested=f"{display_time(r['created_at'])}<div class='muted'>{escape(timing_label)}</div>"
            note=(r['decision_note'] or '').strip()
            if r['status']=='pending':
                decision="<span class='muted'>Awaiting administrator decision</span>"
            else:
                who=escape(r['decided_by'] or 'System')
                when=display_time(r['decided_at'])
                decision=f"<div><b>{who}</b></div>"+(f"<div class='muted'>{escape(when)}</div>" if when else '')
                if note:
                    decision += f"<div class='muted' title='{escape(note)}'>{escape(clipped(note))}</div>"
            actions=request_actions(conn,principal,r) if r['status']=='pending' else f"<a class='button' href='/requests/{r['id']}'>Open</a>"
            rendered.append(f"<tr><td>{app_cell(r['product_name'],r['file_path'],'/requests/%s' % r['id'])}{app_extra}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a><div class='muted'>{escape(r['organization_name'] or '')}</div></td><td>{escape(r['requested_by'] or 'Unknown')}</td><td>{requested}</td><td><span class='badge {cls}'>{escape(status_label)}</span></td><td>{decision}</td><td>{actions}</td></tr>")

    pending=counts.get('pending',0); approving=counts.get('approving',0)
    approved=counts.get('approved',0)+counts.get('approved_existing',0)
    rejected=counts.get('denied',0)+counts.get('blocked',0)
    failed=counts.get('failed',0)+counts.get('approval_failed',0)
    summary=f"<div class='grid'><div class='stat'><span class='stat-label'>Pending</span><b>{pending}</b><span class='trend'>Awaiting administrator action</span></div><div class='stat'><span class='stat-label'>Approving</span><b>{approving}</b><span class='trend'>Endpoint policy work in progress</span></div><div class='stat'><span class='stat-label'>Approved</span><b>{approved}</b><span class='trend'>Approved in current view</span></div><div class='stat'><span class='stat-label'>Denied / Blocked</span><b>{rejected}</b><span class='trend'>Rejected requests</span></div><div class='stat'><span class='stat-label'>Failed</span><b>{failed}</b><span class='trend'>Requires review</span></div></div>"
    statuses=[('', 'All statuses')]+[(v,REQUEST_STATUS_LABELS[v]) for v in ['pending','approving','approved','approved_existing','denied','blocked','failed','revoked']]
    status_options=''.join(f"<option value='{v}' {'selected' if request_status==v else ''}>{escape(label)}</option>" for v,label in statuses)
    kind_options=''.join(f"<option value='{v}' {'selected' if request_kind==v else ''}>{label}</option>" for v,label in [('', 'All request types'),('session','Application/session requests'),('file','Single-file requests')])
    period_options=''.join(f"<option value='{v}' {'selected' if period==v else ''}>{label}</option>" for v,label in [(0,'All time'),(7,'Last 7 days'),(30,'Last 30 days'),(90,'Last 90 days'),(365,'Last 365 days')])
    sort_options=''.join(f"<option value='{v}' {'selected' if sort==v else ''}>{label}</option>" for v,label in [('queue','Action queue first'),('newest','Newest first'),('oldest','Oldest first')])
    org_filter=''
    if principal.can_manage_global:
        org_options="<option value=''>All organizations</option>"+''.join(f"<option value='{o['id']}' {'selected' if organization_id==str(o['id']) else ''}>{escape(o['name'])}</option>" for o in orgs)
        org_filter=f"<div class='field'><label>Organization</label><select name='organization_id'>{org_options}</select></div>"
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='App, device, user, decision'></div>{org_filter}<div class='field'><label>Status</label><select name='request_status'>{status_options}</select></div><div class='field'><label>Type</label><select name='request_kind'>{kind_options}</select></div><div class='field'><label>Period</label><select name='period'>{period_options}</select></div><div class='field'><label>Sort</label><select name='sort'>{sort_options}</select></div><button class='btn-primary'>Filter</button><a href='/requests'><button type='button'>Clear</button></a></form>"
    table=f"<div class='card'><table><tr><th>Application</th><th>Device</th><th>Requested by</th><th>Requested</th><th>Status</th><th>Decision</th><th>Action</th></tr>{''.join(rendered) or '<tr><td colspan=7><div class=\"empty\">No approval requests match these filters.</div></td></tr>'}</table></div>"
    params_nav={'q':q,'request_status':request_status,'organization_id':organization_id,'request_kind':request_kind,'period':period,'sort':sort}
    body=f"{summary}<div class='section-head'><h2>Request Queue & History</h2><span class='muted'>{total} match current filters</span></div>{filters}{table}{pager('/requests',page_num,total,params_nav)}"
    return page('Approval Requests',body,principal,subtitle='Review active requests and searchable decision history from one queue.',actions="<a class='button' href='/reports/approvals'>Decision Report</a><a class='button' href='/reports/approvals.csv'>Export CSV</a>")


@app.get('/requests/{request_id}', response_class=HTMLResponse)
def request_detail(request_id:int, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        r=conn.execute("SELECT r.*,d.hostname,d.organization_id,o.name organization_name FROM approval_requests r JOIN devices d ON d.id=r.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE r.id=?",(request_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Request not found')
        require_org_access(principal,r['organization_id'])
        items=conn.execute('SELECT * FROM approval_request_items WHERE request_id=? ORDER BY id',(request_id,)).fetchall()
        d=conn.execute('SELECT * FROM devices WHERE id=?',(r['device_id'],)).fetchone()
        opts=scope_options_for_device(conn,principal,d)
    rows=''.join(f"<tr><td>{escape(i['product_name'] or '')}</td><td><code>{escape(i['original_path'])}</code></td><td>{escape(i['publisher'] or '')}</td><td>{escape(i['file_version'] or '')}</td><td>{escape(i['parent_path'] or '')}</td><td><code title='{escape(i['sha256'] or '')}'>{escape((i['sha256'] or '')[:20])}</code></td></tr>" for i in items)
    action=''
    if r['status']=='pending' and principal.can_approve:
        action=f"<div class='panel no-print'><h2>Decision</h2><p class='muted'>Approve creates an ALLOW policy at the selected scope. Block creates an explicit BLOCK policy. Deny rejects only this request and can include a message to the end user.</p><form class='actions' method='post' action='/admin/requests/{request_id}/approve'><label>Approval scope</label><select name='scope_type'>{opts}</select><button class='btn-primary'>Approve</button></form><form class='actions' method='post' action='/admin/requests/{request_id}/block'><label>Block scope</label><select name='scope_type'>{opts}</select><button class='btn-danger'>Block</button></form><a class='button btn-warning' href='/requests/{request_id}/deny'>Deny request</a></div>"
    status_label=request_status_label(r['status']); status_cls=request_status_class(r['status'])
    request_kind='Application/session request' if (r['request_kind'] or 'file')=='session' else 'Single-file request'
    component_count=int(r['component_count'] or len(items) or 1) if 'component_count' in r.keys() else (len(items) or 1)
    elapsed=elapsed_label(r['created_at'],r['decided_at'] if r['status'] not in {'pending','approving'} else None)
    elapsed_title='Open for' if r['status'] in {'pending','approving'} else 'Time to decision'
    decided_by=escape(r['decided_by'] or '—'); decided_at=display_time(r['decided_at']) or '—'
    reason=escape((r['reason'] or '').strip() or 'No reason supplied.')
    note=escape((r['decision_note'] or '').strip() or 'No decision message recorded.')
    details=f"""<div class='panel'><div class='details-grid'>
      <div class='detail-item'><span class='muted'>Application</span>{app_cell(r['product_name'],r['file_path'])}</div>
      <div class='detail-item'><span class='muted'>Status</span><span class='badge {status_cls}'>{escape(status_label)}</span></div>
      <div class='detail-item'><span class='muted'>Device</span><b><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a></b><div class='muted'>{escape(r['organization_name'] or '')}</div></div>
      <div class='detail-item'><span class='muted'>Requested by</span><b>{escape(r['requested_by'] or 'Unknown')}</b></div>
      <div class='detail-item'><span class='muted'>Request type</span><b>{escape(request_kind)}</b><div class='muted'>{component_count} component{'s' if component_count!=1 else ''}</div></div>
      <div class='detail-item'><span class='muted'>Requested</span><b>{escape(display_time(r['created_at']))}</b><div class='muted'>{escape(elapsed_title)}: {escape(elapsed or '—')}</div></div>
      <div class='detail-item'><span class='muted'>Decided by</span><b>{decided_by}</b></div>
      <div class='detail-item'><span class='muted'>Decision time</span><b>{escape(decided_at)}</b></div>
    </div></div>"""
    message_panels=f"<div class='grid'><div class='panel'><h3>User request reason</h3><p>{reason}</p></div><div class='panel'><h3>Administrator decision message</h3><p>{note}</p></div></div>"
    component_table=f"<div class='section-head'><h2>Request Components</h2><span class='muted'>{component_count} component{'s' if component_count!=1 else ''}</span></div><div class='card'><table><tr><th>Product</th><th>File</th><th>Publisher</th><th>Version</th><th>Loaded by</th><th>SHA256</th></tr>{rows or '<tr><td colspan=6><div class=\"empty\">No component detail was captured for this request.</div></td></tr>'}</table></div>"
    body=f"{details}{message_panels}{action}{component_table}"
    return page(f'Approval Request #{request_id}',body,principal,subtitle='Request details, decision history and captured application components.',actions="<a class='button' href='/requests'>Back to Requests</a><a class='button' href='/reports/approvals'>Decision Report</a>")


@app.get('/devices/{device_id}', response_class=HTMLResponse)
def device_detail(device_id:str, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        d=conn.execute("SELECT d.*,o.name organization_name,g.name group_name FROM devices d LEFT JOIN organizations o ON o.id=d.organization_id LEFT JOIN device_groups g ON g.id=d.group_id WHERE d.id=?",(device_id,)).fetchone()
        if not d: raise HTTPException(status_code=404,detail='Device not found')
        require_org_access(principal,d['organization_id'])
        groups=conn.execute('SELECT * FROM device_groups WHERE organization_id=? ORDER BY name',(d['organization_id'],)).fetchall()
        approvals=conn.execute("SELECT * FROM approved_components WHERE device_id=? ORDER BY id DESC LIMIT 100",(device_id,)).fetchall()
        blocks=conn.execute("SELECT * FROM blocked_applications WHERE device_id=? ORDER BY id DESC LIMIT 100",(device_id,)).fetchall()
        requests=conn.execute("SELECT * FROM approval_requests WHERE device_id=? ORDER BY id DESC LIMIT 100",(device_id,)).fetchall()
        events=conn.execute("SELECT * FROM events WHERE device_id=? ORDER BY id DESC LIMIT 150",(device_id,)).fetchall()
        commands=conn.execute("SELECT * FROM commands WHERE device_id=? ORDER BY id DESC LIMIT 100",(device_id,)).fetchall()
        audits=conn.execute("SELECT * FROM audit_log WHERE device_id=? ORDER BY id DESC LIMIT 100",(device_id,)).fetchall()
        effective=[r for r in conn.execute("SELECT * FROM scoped_policies WHERE active=1 ORDER BY CASE action WHEN 'block' THEN 0 ELSE 1 END,id DESC").fetchall() if device_matches_policy_scope(conn,device_id,r)]
        pol_rows=[]
        for r in effective:
            cls='badge-bad' if r['action']=='block' else 'badge-ok'
            pol_rows.append(f"<tr><td><span class='badge {cls}'>{escape(r['action'].upper())}</span></td><td>{escape(r['name'])}</td><td>{escape(policy_scope_label(conn,r))}</td><td>{escape(r['publisher'] or '')}</td><td>{escape(r['product_name'] or '')}</td></tr>")
    timeline=[]
    for e in events[:80]: timeline.append((e['occurred_at'] or e['received_at'], 'Blocked by App Control' if e['event_id']==3077 else ('Observed / Audit' if e['event_id']==3076 else 'Event '+str(e['event_id'])), e['product_name'] or e['file_path'] or ''))
    for r in requests[:50]: timeline.append((r['created_at'],'Approval request '+r['status'],r['product_name'] or r['file_path']))
    for c in commands[:50]: timeline.append((c['created_at'],'Command '+c['command_type']+' / '+c['status'],c['result'] or ''))
    for a in audits[:50]: timeline.append((a['occurred_at'],a['action'],a['detail'] or ''))
    timeline=sorted(timeline,key=lambda x:x[0] or '',reverse=True)[:150]
    group_form=''
    if principal.can_manage_org:
        opts="<option value=''>No group</option>"+''.join(f"<option value='{g['id']}' {'selected' if d['group_id']==g['id'] else ''}>{escape(g['name'])}</option>" for g in groups)
        group_form=f"<form class='actions' method='post' action='/admin/devices/{device_id}/group'><label>Device group</label><select name='group_id'>{opts}</select><button>Save</button></form>"
    appr=''.join(f"<tr><td>{escape(a['product_name'] or '')}</td><td><code>{escape(a['file_path'])}</code></td><td>{escape(a['rule_type'] or '')}</td><td>{escape(a['status'] or '')}</td><td>{escape(a['approved_at'] or '')}</td></tr>" for a in approvals)
    blk=''.join(f"<tr><td>{escape(b['product_name'] or '')}</td><td><code>{escape(b['file_path'])}</code></td><td>{escape(b['status'])}</td><td>{escape(b['blocked_at'] or b['created_at'])}</td></tr>" for b in blocks)
    reqs=''.join(f"<tr><td><a href='/requests/{r['id']}'>{r['id']}</a></td><td>{escape(r['product_name'] or '')}</td><td>{escape(r['status'])}</td><td>{escape(r['requested_by'] or '')}</td><td>{escape(r['created_at'])}</td></tr>" for r in requests)
    hist=''.join(f"<tr><td>{escape(t or '')}</td><td>{escape(k)}</td><td><code>{escape(v or '')}</code></td></tr>" for t,k,v in timeline)
    policies=''.join(pol_rows)
    with db() as conn:
        active_releases=conn.execute("SELECT * FROM agent_releases WHERE active=1 AND deleted_at IS NULL ORDER BY id DESC").fetchall()
        update_history=conn.execute("SELECT h.*,r.channel FROM agent_update_history h LEFT JOIN agent_releases r ON r.id=h.release_id WHERE h.device_id=? ORDER BY h.id DESC LIMIT 10",(device_id,)).fetchall()
    release_opts=''.join(f"<option value='{r['id']}'>{escape(r['version'])} ({escape(r['channel'])})</option>" for r in active_releases)
    update_panel=f"<div class='panel'><h2>Agent Update</h2><div class='details-grid'><div class='detail-item'><span class='muted'>Current version</span><b>{escape(d['agent_version'] or '')}</b></div><div class='detail-item'><span class='muted'>Desired version</span><b>{escape(d['desired_agent_version'] or 'None')}</b></div><div class='detail-item'><span class='muted'>Update status</span><b>{escape((d['update_status'] or 'None').replace('_',' ').title())}</b></div><div class='detail-item'><span class='muted'>Last result</span>{escape(d['update_result'] or '')}</div></div>" + (f"<form class='actions' method='post' action='/admin/devices/{device_id}/agent-update'><select name='release_id'>{release_opts}</select><button class='btn-primary'>Update Agent</button></form>" if principal.can_manage_org and release_opts else '') + "<p class='muted'>Managed self-update requires agent 0.10.0 or later. The updater verifies SHA256, stages the package, pre-authorizes new binaries for App Control, backs up the current install and automatically rolls back if the replacement service does not start.</p></div>"
    if update_history:
        update_panel += "<div class='card'><table><tr><th>From</th><th>Target</th><th>Status</th><th>Started</th><th>Completed</th><th>Detail</th></tr>"+''.join(f"<tr><td>{escape(h['from_version'] or '')}</td><td>{escape(h['target_version'])}</td><td>{escape(h['status'])}</td><td>{display_time(h['created_at'])}</td><td>{display_time(h['completed_at'])}</td><td>{escape(h['detail'] or '')}</td></tr>" for h in update_history)+"</table></div>"
    can_delete, delete_reason = device_record_can_be_deleted(d)
    lifecycle_actions=''
    if principal.can_manage_org:
        offboard=(d['offboard_status'] or '').lower()
        if offboard not in {'queued','uninstalling','completed'}:
            label='Retry Uninstall' if offboard=='failed' else 'Uninstall Agent'
            if version_at_least(d['agent_version'],'0.11.0'):
                lifecycle_actions += f"""<form method='post' action='/admin/devices/{device_id}/uninstall' onsubmit=\"return confirm('Uninstall AppControl Manager from {escape(d['hostname'])}? AppControl Manager Windows App Control policies will be removed before the agent and tray are removed.');\"><button class='btn-danger'>{label}</button></form>"""
            else:
                lifecycle_actions += "<button type='button' disabled title='Update this device to agent 0.11.0 or later first.'>Uninstall Agent</button>"
        if can_delete:
            lifecycle_actions += f"<form method='post' action='/admin/devices/{device_id}/delete' onsubmit=\"return confirm('Permanently delete the server record and stored device history for {escape(d['hostname'])}? This cannot be undone.');\"><button class='btn-danger'>Delete Device Record</button></form>"
    lifecycle_panel=f"<div class='panel'><h2>Device Lifecycle</h2><div class='details-grid'><div class='detail-item'><span class='muted'>Offboarding</span><b>{escape((d['offboard_status'] or 'Active').replace('_',' ').title())}</b></div><div class='detail-item'><span class='muted'>Offboarding result</span>{escape(d['offboard_result'] or '')}</div><div class='detail-item'><span class='muted'>Record cleanup</span>{escape(delete_reason)}</div></div><div class='actions'>{lifecycle_actions}</div><p class='muted'>Remote uninstall removes AppControl Manager-managed Windows App Control policies first, then removes the tray, service, program files and local AppControl Manager data. Stale server records can be deleted after {STALE_DEVICE_DAYS} days without a check-in, or immediately after successful offboarding.</p></div>"
    mode_name=display_mode(d)
    mode_action=''
    if principal.can_approve and (d['offboard_status'] or '').lower() not in {'queued','uninstalling','completed'}:
        if mode_name=='Learning':
            mode_action=f"<form method='post' action='/admin/devices/{device_id}/enforcement'><button class='btn-primary'>Enable Enforcement</button></form>"
        else:
            mode_action=f"<form method='post' action='/admin/devices/{device_id}/learning'><button>Return to Learning</button></form>"
    status_online=bool(d['last_seen'] and d['last_seen']>=(datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat())
    status_badge=f"<span class='badge {'badge-ok' if status_online else 'badge-warn'}'>{'Online' if status_online else 'Offline'}</span>"
    control_panel=f"<div class='panel'><div class='section-head' style='margin-top:0'><h2>Device Control</h2><div class='actions'>{mode_action}</div></div><div class='details-grid'><div class='detail-item'><span class='muted'>Connectivity</span>{status_badge}</div><div class='detail-item'><span class='muted'>OS</span><b>{escape(d['os_version'] or '')}</b></div><div class='detail-item'><span class='muted'>Last Seen</span><b>{display_time(d['last_seen']) or 'Never'}</b></div><div class='detail-item'><span class='muted'>Device ID</span><code>{escape(d['id'])}</code></div></div>{group_form}</div>"
    jump="<div class='actions no-print' style='margin-bottom:18px'><a class='button btn-quiet' href='#policies'>Effective Policies</a><a class='button btn-quiet' href='#activity'>Activity</a><a class='button btn-quiet' href='#approved-apps'>Approvals</a><a class='button btn-quiet' href='#blocked-apps'>Blocks</a><a class='button btn-quiet' href='#requests'>Requests</a></div>"
    body=f"""<div class='grid'><div class='stat'><span class='stat-label'>Organization</span><b style='font-size:18px'>{escape(d['organization_name'] or '')}</b></div><div class='stat'><span class='stat-label'>Device Group</span><b style='font-size:18px'>{escape(d['group_name'] or 'None')}</b></div><div class='stat'><span class='stat-label'>App Control Mode</span><b style='font-size:18px'>{escape(mode_name)}</b></div><div class='stat'><span class='stat-label'>Agent Version</span><b style='font-size:18px'>{escape(d['agent_version'] or '')}</b></div></div>
{jump}{control_panel}
<div id='policies' class='section-head'><h2>Effective Scoped Policies</h2><a href='/reports/policies?device_id={quote(device_id)}'>Device Policy Report →</a></div><div class='card'><table><tr><th>Action</th><th>Application</th><th>Scope</th><th>Publisher</th><th>Product</th></tr>{policies or '<tr><td colspan=5><div class=empty>No active scoped policies apply to this device.</div></td></tr>'}</table></div>
<div id='activity' class='section-head'><h2>Activity / History</h2><a href='/reports/blocked-events?device_id={quote(device_id)}'>Blocked Event Report →</a></div><div class='card'><table><tr><th>Time</th><th>Activity</th><th>Detail</th></tr>{hist or '<tr><td colspan=3><div class=empty>No activity.</div></td></tr>'}</table></div>
<div id='approved-apps' class='section-head'><h2>Approved Applications</h2></div><div class='card'><table><tr><th>Product</th><th>File</th><th>Rule</th><th>Status</th><th>Approved</th></tr>{appr or '<tr><td colspan=5><div class=empty>No approvals.</div></td></tr>'}</table></div>
<div id='blocked-apps' class='section-head'><h2>Blocked Applications</h2></div><div class='card'><table><tr><th>Product</th><th>File</th><th>Status</th><th>Blocked</th></tr>{blk or '<tr><td colspan=4><div class=empty>No explicit blocks.</div></td></tr>'}</table></div>
<div id='requests' class='section-head'><h2>Approval Requests</h2><a href='/reports/approvals?device_id={quote(device_id)}'>Decision Report →</a></div><div class='card'><table><tr><th>ID</th><th>Product</th><th>Status</th><th>User</th><th>Created</th></tr>{reqs or '<tr><td colspan=5><div class=empty>No requests.</div></td></tr>'}</table></div>"""
    report_actions_html=f"<a class='button' href='/reports/device-compliance?device_id={quote(device_id)}'>Device Report</a><a class='button' href='/reports/device-compliance.csv?device_id={quote(device_id)}'>Export CSV</a>"
    subtitle=f"{d['organization_name'] or ''} · {d['group_name'] or 'No group'} · {mode_name}"
    return page(d['hostname'],body+update_panel+lifecycle_panel,principal,subtitle=subtitle,actions=report_actions_html)



def filtered_rows(conn, principal, sql_global, sql_org, params=()):
    if principal.can_manage_global:
        return conn.execute(sql_global, params).fetchall()
    return conn.execute(sql_org, (*params, principal.organization_id)).fetchall()


@app.get('/approved', response_class=HTMLResponse)
def approved_page(busy:int=0,q:str='',page_num:int=Query(1,alias='page'),principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num); html=[]
    with db() as conn:
        clause,params=visible_device_clause(principal,'d'); where=[clause,"COALESCE(a.status,'approved')<>'revoked'"]; args=list(params)
        if q:
            term=f"%{q.lower()}%"; where.append("(lower(COALESCE(a.product_name,'')) LIKE ? OR lower(a.file_path) LIKE ? OR lower(COALESCE(a.publisher,'')) LIKE ? OR lower(d.hostname) LIKE ?)"); args += [term]*4
        where_sql=' AND '.join(where)
        total=conn.execute(f"SELECT COUNT(*) n FROM approved_components a JOIN devices d ON d.id=a.device_id WHERE {where_sql}",args).fetchone()['n']
        rows=conn.execute(f"""SELECT a.*,d.hostname,d.organization_id,d.group_id,o.name organization_name,p.scope_type,p.id scoped_policy_id,(SELECT COUNT(*) FROM approved_components x WHERE x.device_id=a.device_id AND x.policy_id=a.policy_id) policy_component_count FROM approved_components a JOIN devices d ON d.id=a.device_id LEFT JOIN organizations o ON o.id=d.organization_id LEFT JOIN scoped_policies p ON p.id=a.policy_definition_id WHERE {where_sql} ORDER BY a.id DESC LIMIT ? OFFSET ?""",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
        for r in rows:
            current=r['status'] or 'approved'; actions=''
            if current=='approved' and principal.can_approve and re.fullmatch(r'[0-9A-Fa-f-]{36}',r['policy_id'] or ''):
                revoke_label='Disable scoped approval' if r['scoped_policy_id'] else 'Revoke'; opts=scope_options_for_device(conn,principal,r)
                actions=(f"<div class='action-stack'><form method='post' action='/admin/approved/{r['id']}/revoke'><button class='btn-warning'>{revoke_label}</button></form>"
                         f"<div class='block-action'><span class='action-label'>Block at scope</span><form class='actions' method='post' action='/admin/approved/{r['id']}/block'><select class='scope-select' name='scope_type'>{opts}</select><button class='btn-danger'>Block</button></form></div></div>")
            component_note=f"<div class='muted'>{r['policy_component_count']} components in policy</div>" if (r['policy_component_count'] or 0)>1 else ''
            apphtml=app_cell(r['product_name'],r['file_path'])+component_note
            html.append(f"<tr><td>{apphtml}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a><div class='muted'>{escape(r['organization_name'] or '')}</div></td><td><div class='publisher-short' title='{escape(r['publisher'] or '')}'>{escape(short_publisher(r['publisher']))}</div></td><td>{escape(r['rule_type'] or '')}</td><td>{escape(r['scope_type'] or 'device').title()}</td><td><span class='badge badge-ok'>{escape(current.title())}</span></td><td>{actions}</td></tr>")
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Application, publisher or device'></div><button class='btn-primary'>Filter</button><a href='/approved'><button type='button'>Clear</button></a></form>"
    body=("<div class='notice'>Device policy operation already in progress.</div>" if busy else '')+filters+f"<div class='card'><table><tr><th>Application</th><th>Device</th><th>Publisher</th><th>Rule</th><th>Approval Scope</th><th>Status</th><th>Actions</th></tr>{''.join(html) or '<tr><td colspan=7><div class=\"empty\">No approvals match these filters.</div></td></tr>'}</table></div>{pager('/approved',page_num,total,{'q':q})}"
    return page('Approved Applications',body,principal,subtitle='Current endpoint application approvals. Revoke an approval independently or create a scoped explicit BLOCK.',actions="<a class='button' href='/reports/policies'>Policy Report</a>")


@app.get('/learned', response_class=HTMLResponse)
def learned_page(q:str='', page_num:int=Query(1,alias='page'), principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    with db() as conn:
        clause,params=visible_device_clause(principal,'d')
        where=[clause,"e.event_id=3076","e.file_path IS NOT NULL","e.file_path<>''"]
        args=list(params)
        if q:
            term=f"%{q.lower()}%"
            where.append("(lower(COALESCE(e.product_name,'')) LIKE ? OR lower(e.file_path) LIKE ? OR lower(COALESCE(e.publisher,'')) LIKE ? OR lower(d.hostname) LIKE ?)")
            args += [term]*4
        where_sql=' AND '.join(where)
        total=conn.execute(f"SELECT COUNT(*) n FROM (SELECT e.device_id,lower(e.file_path) fp FROM events e JOIN devices d ON d.id=e.device_id WHERE {where_sql} GROUP BY e.device_id,lower(e.file_path))",args).fetchone()['n']
        rows=conn.execute(f"""SELECT e.*,d.hostname,d.organization_id,d.group_id FROM events e JOIN devices d ON d.id=e.device_id
            JOIN (SELECT MAX(e2.id) id FROM events e2 WHERE e2.event_id=3076 AND e2.file_path IS NOT NULL AND e2.file_path<>'' GROUP BY e2.device_id,lower(e2.file_path)) latest ON latest.id=e.id
            WHERE {where_sql} ORDER BY e.id DESC LIMIT ? OFFSET ?""",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
        html=[]
        for r in rows:
            action=''
            if principal.can_approve:
                opts=scope_options_for_device(conn,principal,r)
                action=f"<form class='actions' method='post' action='/admin/observed/{r['id']}/block'><select class='scope-select' name='scope_type'>{opts}</select><button class='btn-danger'>Block</button></form>"
            html.append(f"<tr><td>{app_cell(r['product_name'],r['file_path'],'/events/%s' % r['id'])}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a></td><td><div class='publisher-short' title='{escape(r['publisher'] or '')}'>{escape(short_publisher(r['publisher']))}</div></td><td>{escape(r['file_version'] or '')}</td><td class='nowrap'>{display_time(r['occurred_at'] or r['received_at'])}</td><td>{action}</td></tr>")
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Application, file, publisher, device'></div><button class='btn-primary'>Filter</button><a href='/learned'><button type='button'>Clear</button></a></form>"
    return page('Learned / Observed Applications',f"{filters}<div class='card'><table><tr><th>Application</th><th>Device</th><th>Publisher</th><th>Version</th><th>Last observed</th><th>Action / scope</th></tr>{''.join(html) or '<tr><td colspan=6><div class=empty>No observed applications match these filters.</div></td></tr>'}</table></div>{pager('/learned',page_num,total,{'q':q})}",principal,subtitle='Learning-mode observations summarized by application and device. Open an event for full forensic detail.',actions="<a class='button' href='/reports/application-activity'>Activity Report</a>")


@app.get('/events/{event_row_id}', response_class=HTMLResponse)
def event_detail(event_row_id:int, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        r=conn.execute("SELECT e.*,d.hostname,d.organization_id,d.group_id,o.name organization_name FROM events e JOIN devices d ON d.id=e.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE e.id=?",(event_row_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Event not found')
        require_org_access(principal,r['organization_id'])
        related_block=related_block_for_event(conn,r) if r['event_id']==3077 else None
        related_request=related_request_for_event(conn,r) if r['event_id']==3077 else None
        active_block=conn.execute("SELECT * FROM blocked_applications WHERE device_id=? AND lower(file_path)=lower(?) AND status IN ('blocking','blocked','unblocking') ORDER BY id DESC LIMIT 1",(r['device_id'],r['file_path'] or '')).fetchone() if r['file_path'] else None
        action=''
        if principal.can_approve and r['event_id'] in (3076,3077):
            if active_block:
                action=f"<div class='notice-info'><b>Explicit block already exists:</b> <a href='/blocked/{active_block['id']}'>Block #{active_block['id']}</a> is {escape(block_status_label(active_block['status']).lower())} on this device.</div>"
            else:
                opts=scope_options_for_device(conn,principal,r)
                action=f"<div class='panel'><h2>Create explicit block</h2><p class='muted'>Create a device, group, organization or global deny policy from this observed identity.</p><form class='actions' method='post' action='/admin/observed/{r['id']}/block'><select name='scope_type'>{opts}</select><button class='btn-danger'>Block</button></form></div>"
        context=''
        if r['event_id']==3077:
            classification='Explicit AppControl Manager block' if related_block else 'Not allowed by current App Control policy'
            block_html=(f"<a href='/blocked/{related_block['id']}'><b>Block #{related_block['id']}</b></a><div class='muted'>{escape(block_status_label(related_block['status']))}</div>" if related_block else "<span class='muted'>No explicit AppControl Manager block was active at the time of this event.</span>")
            if related_request:
                rcls=request_status_class(related_request['status'])
                note=(related_request['decision_note'] or '').strip()
                request_html=f"<a href='/requests/{related_request['id']}'><b>Request #{related_request['id']}</b></a> <span class='badge {rcls}'>{escape(request_status_label(related_request['status']))}</span>"
                if note: request_html+=f"<div class='muted' title='{escape(note)}'>{escape(clipped(note,220))}</div>"
            else:
                request_html="<span class='muted'>No approval request was recorded within seven days of this block event.</span>"
            context=f"""<div class='section-head'><h2>Block Context</h2></div><div class='panel'><div class='details-grid'>
              <div class='detail-item'><span class='muted'>Classification</span><b>{escape(classification)}</b></div>
              <div class='detail-item'><span class='muted'>Related explicit block</span>{block_html}</div>
              <div class='detail-item'><span class='muted'>Related approval request</span>{request_html}</div>
            </div></div>"""
    raw=''
    if r['raw_json']:
        raw=f"<details class='panel'><summary><b>Raw event data</b></summary><pre style='white-space:pre-wrap;word-break:break-word'>{escape(r['raw_json'])}</pre></details>"
    body=f"""<div class='panel'><div class='details-grid'>
      <div class='detail-item'><span class='muted'>Application</span><b>{escape(r['product_name'] or filename(r['file_path']))}</b></div>
      <div class='detail-item'><span class='muted'>Device</span><a href='/devices/{r['device_id']}'><b>{escape(r['hostname'])}</b></a><div class='muted'>{escape(r['organization_name'] or '')}</div></div>
      <div class='detail-item'><span class='muted'>Event</span><b>{'Blocked (3077)' if r['event_id']==3077 else 'Observed / Audit (3076)' if r['event_id']==3076 else escape(str(r['event_id']))}</b></div>
      <div class='detail-item'><span class='muted'>Observed</span><b>{display_time(r['occurred_at'] or r['received_at'])}</b></div>
      <div class='detail-item'><span class='muted'>Version</span><b>{escape(r['file_version'] or '')}</b></div>
      <div class='detail-item'><span class='muted'>CI record ID</span><b>{r['record_id'] or ''}</b></div>
    </div><div class='detail-item'><span class='muted'>Full path</span><code>{escape(r['file_path'] or '')}</code></div><div class='detail-item'><span class='muted'>Parent process</span><code>{escape(r['parent_path'] or '')}</code></div><div class='detail-item'><span class='muted'>Publisher</span>{escape(r['publisher'] or '')}</div><div class='detail-item'><span class='muted'>SHA256</span><code>{escape(r['sha256'] or '')}</code></div></div>{context}{action}{raw}"""
    return page('Application Event Details',body,principal,actions="<a class='button' href='/blocked-events'>Back to Blocked Activity</a>" if r['event_id']==3077 else '')


@app.get('/block-activity', response_class=HTMLResponse)
@app.get('/blocked-events', response_class=HTMLResponse)
def block_activity_page(q:str='', reason_type:str='', organization_id:str='', period:int=30, sort:str='newest',
                        page_num:int=Query(1,alias='page'), principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    period=period if period in {0,7,30,90,365} else 30
    reason_type=reason_type if reason_type in {'','explicit','policy'} else ''
    sort=sort if sort in {'newest','oldest'} else 'newest'
    with db() as conn:
        clause,params=visible_device_clause(principal,'d')
        where=[clause,"e.event_id=3077","e.file_path IS NOT NULL","e.file_path<>''"]
        args=list(params)
        if principal.can_manage_global and organization_id:
            try: org_id=int(organization_id)
            except ValueError: org_id=None
            if org_id is not None:
                where.append('d.organization_id=?'); args.append(org_id)
            else: organization_id=''
        if period:
            cutoff=(datetime.now(timezone.utc)-timedelta(days=period)).isoformat()
            where.append('COALESCE(e.occurred_at,e.received_at)>=?'); args.append(cutoff)
        if q:
            term=f"%{q.lower()}%"
            where.append("(lower(COALESCE(e.product_name,'')) LIKE ? OR lower(e.file_path) LIKE ? OR lower(COALESCE(e.publisher,'')) LIKE ? OR lower(d.hostname) LIKE ? OR lower(COALESCE(o.name,'')) LIKE ?)")
            args += [term]*5
        explicit_expr="""EXISTS (SELECT 1 FROM blocked_applications bx WHERE bx.device_id=e.device_id AND lower(bx.file_path)=lower(e.file_path) AND bx.created_at<=COALESCE(e.occurred_at,e.received_at) AND (bx.unblocked_at IS NULL OR bx.unblocked_at>=COALESCE(e.occurred_at,e.received_at)) AND bx.status<>'failed')"""
        if reason_type=='explicit': where.append(explicit_expr)
        elif reason_type=='policy': where.append(f'NOT ({explicit_expr})')
        where_sql=' AND '.join(where)
        total=conn.execute(f"SELECT COUNT(*) n FROM events e JOIN devices d ON d.id=e.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {where_sql}",args).fetchone()['n']
        summary_row=conn.execute(f"""SELECT COUNT(*) total,
            SUM(CASE WHEN {explicit_expr} THEN 1 ELSE 0 END) explicit_count,
            COUNT(DISTINCT e.device_id) devices,
            COUNT(DISTINCT COALESCE(NULLIF(e.product_name,''),lower(e.file_path))) applications
            FROM events e JOIN devices d ON d.id=e.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {where_sql}""",args).fetchone()
        order_sql='e.id DESC' if sort=='newest' else 'e.id ASC'
        rows=conn.execute(f"""SELECT e.*,d.hostname,d.organization_id,d.group_id,o.name organization_name,
               CASE WHEN {explicit_expr} THEN 'Explicit block' ELSE 'Not allowed by policy' END block_type
               FROM events e JOIN devices d ON d.id=e.device_id LEFT JOIN organizations o ON o.id=d.organization_id
               WHERE {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?""",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
        orgs=conn.execute("SELECT id,name FROM organizations WHERE status='active' ORDER BY name").fetchall() if principal.can_manage_global else []
        html=[]
        for r in rows:
            related_block=related_block_for_event(conn,r)
            related_request=related_request_for_event(conn,r)
            reason_html=f"<span class='badge {'badge-bad' if related_block else 'badge-warn'}'>{escape(r['block_type'])}</span>"
            if related_block:
                reason_html+=f"<div class='muted'><a href='/blocked/{related_block['id']}'>Block #{related_block['id']}</a> · {escape(block_status_label(related_block['status']))}</div>"
            request_html="<span class='muted'>None nearby</span>"
            if related_request:
                note=(related_request['decision_note'] or '').strip()
                request_html=f"<a href='/requests/{related_request['id']}'>Request #{related_request['id']}</a><div><span class='badge {request_status_class(related_request['status'])}'>{escape(request_status_label(related_request['status']))}</span></div>"
                if note: request_html+=f"<div class='muted' title='{escape(note)}'>{escape(clipped(note,120))}</div>"
            action=f"<a class='button' href='/events/{r['id']}'>Open</a>"
            if principal.can_approve and not related_block:
                opts=scope_options_for_device(conn,principal,r)
                action+=f"<form class='actions' method='post' action='/admin/observed/{r['id']}/block'><select class='scope-select' name='scope_type'>{opts}</select><button class='btn-danger'>Block</button></form>"
            html.append(f"<tr><td class='nowrap'>{display_time(r['occurred_at'] or r['received_at'])}</td><td>{app_cell(r['product_name'],r['file_path'],'/events/%s' % r['id'])}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a><div class='muted'>{escape(r['organization_name'] or '')}</div></td><td><div class='publisher-short' title='{escape(r['publisher'] or '')}'>{escape(short_publisher(r['publisher']))}</div></td><td>{reason_html}</td><td>{request_html}</td><td><div class='action-stack'>{action}</div></td></tr>")
    explicit_count=int(summary_row['explicit_count'] or 0); policy_count=int(summary_row['total'] or 0)-explicit_count
    summary=f"<div class='grid'><div class='stat'><span class='stat-label'>Blocked Events</span><b>{summary_row['total'] or 0}</b><span class='trend'>{'All time' if period==0 else f'Last {period} days'}</span></div><div class='stat'><span class='stat-label'>Explicit Blocks</span><b>{explicit_count}</b><span class='trend'>Matched an AppControl Manager deny</span></div><div class='stat'><span class='stat-label'>Policy Blocks</span><b>{policy_count}</b><span class='trend'>Not allowed by current policy</span></div><div class='stat'><span class='stat-label'>Applications</span><b>{summary_row['applications'] or 0}</b><span class='trend'>Distinct blocked identities</span></div><div class='stat'><span class='stat-label'>Affected Devices</span><b>{summary_row['devices'] or 0}</b><span class='trend'>Devices in current view</span></div></div>"
    reason_options=''.join(f"<option value='{v}' {'selected' if reason_type==v else ''}>{label}</option>" for v,label in [('', 'All block reasons'),('explicit','Explicit AppControl Manager blocks'),('policy','Not allowed by policy')])
    period_options=''.join(f"<option value='{v}' {'selected' if period==v else ''}>{label}</option>" for v,label in [(7,'Last 7 days'),(30,'Last 30 days'),(90,'Last 90 days'),(365,'Last 365 days'),(0,'All time')])
    sort_options=''.join(f"<option value='{v}' {'selected' if sort==v else ''}>{label}</option>" for v,label in [('newest','Newest first'),('oldest','Oldest first')])
    org_filter=''
    if principal.can_manage_global:
        org_options="<option value=''>All organizations</option>"+''.join(f"<option value='{o['id']}' {'selected' if organization_id==str(o['id']) else ''}>{escape(o['name'])}</option>" for o in orgs)
        org_filter=f"<div class='field'><label>Organization</label><select name='organization_id'>{org_options}</select></div>"
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Application, file, publisher, device'></div>{org_filter}<div class='field'><label>Reason</label><select name='reason_type'>{reason_options}</select></div><div class='field'><label>Period</label><select name='period'>{period_options}</select></div><div class='field'><label>Sort</label><select name='sort'>{sort_options}</select></div><button class='btn-primary'>Filter</button><a href='/blocked-events'><button type='button'>Clear</button></a></form>"
    params_nav={'q':q,'reason_type':reason_type,'organization_id':organization_id,'period':period,'sort':sort}
    body=f"{summary}<div class='section-head'><h2>Blocked Activity</h2><span class='muted'>{total} match current filters</span></div><p class='muted'>Block telemetry is correlated with explicit deny records and nearby approval requests so you can see what was blocked and what happened afterward.</p>{filters}<div class='card'><table><tr><th>Time</th><th>Application</th><th>Device</th><th>Publisher</th><th>Reason</th><th>Related Request</th><th>Action</th></tr>{''.join(html) or '<tr><td colspan=7><div class=empty>No blocked events match these filters.</div></td></tr>'}</table></div>{pager('/blocked-events',page_num,total,params_nav)}"
    return page('Blocked Activity',body,principal,subtitle='Correlated Windows App Control block telemetry, explicit denies and approval outcomes.',actions="<a class='button' href='/blocked'>Explicit Blocks</a><a class='button' href='/reports/blocked-events'>Blocked Event Report</a><a class='button' href='/reports/blocked-events.csv'>Export CSV</a>")


@app.get('/blocked', response_class=HTMLResponse)
def blocked_page(q:str='', block_status:str='active', scope_type:str='', organization_id:str='', period:int=0, sort:str='newest',
                 busy:int=0, page_num:int=Query(1,alias='page'), principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    block_status=block_status if block_status in {'active','all','blocking','blocked','unblocking','unblocked','failed'} else 'active'
    scope_type=scope_type if scope_type in {'','device','scoped'} else ''
    period=period if period in {0,7,30,90,365} else 0
    sort=sort if sort in {'newest','oldest'} else 'newest'
    with db() as conn:
        clause,params=visible_device_clause(principal,'d')
        base_where=[clause]; base_args=list(params)
        if principal.can_manage_global and organization_id:
            try: org_id=int(organization_id)
            except ValueError: org_id=None
            if org_id is not None:
                base_where.append('d.organization_id=?'); base_args.append(org_id)
            else: organization_id=''
        if period:
            cutoff=(datetime.now(timezone.utc)-timedelta(days=period)).isoformat(); base_where.append('b.created_at>=?'); base_args.append(cutoff)
        if scope_type=='device': base_where.append('b.policy_definition_id IS NULL')
        elif scope_type=='scoped': base_where.append('b.policy_definition_id IS NOT NULL')
        if q:
            term=f"%{q.lower()}%"
            base_where.append("(lower(COALESCE(b.product_name,'')) LIKE ? OR lower(b.file_path) LIKE ? OR lower(COALESCE(b.publisher,'')) LIKE ? OR lower(d.hostname) LIKE ? OR lower(COALESCE(o.name,'')) LIKE ? OR lower(COALESCE(b.blocked_by,'')) LIKE ? OR lower(COALESCE(b.note,'')) LIKE ?)")
            base_args += [term]*7
        base_sql=' AND '.join(base_where)
        summary_rows=conn.execute(f"SELECT b.status,COUNT(*) n FROM blocked_applications b JOIN devices d ON d.id=b.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {base_sql} GROUP BY b.status",base_args).fetchall()
        counts={r['status']:r['n'] for r in summary_rows}
        where=list(base_where); args=list(base_args)
        if block_status=='active': where.append("b.status<>'unblocked'")
        elif block_status!='all': where.append('b.status=?'); args.append(block_status)
        where_sql=' AND '.join(where)
        total=conn.execute(f"SELECT COUNT(*) n FROM blocked_applications b JOIN devices d ON d.id=b.device_id LEFT JOIN organizations o ON o.id=d.organization_id WHERE {where_sql}",args).fetchone()['n']
        order_sql='b.id DESC' if sort=='newest' else 'b.id ASC'
        rows=conn.execute(f"""SELECT b.*,d.hostname,d.organization_id,o.name organization_name,p.scope_type policy_scope_type,p.scope_id,p.active scoped_active,p.id scoped_policy_id
            FROM blocked_applications b JOIN devices d ON d.id=b.device_id LEFT JOIN organizations o ON o.id=d.organization_id LEFT JOIN scoped_policies p ON p.id=b.policy_definition_id
            WHERE {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?""",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
        orgs=conn.execute("SELECT id,name FROM organizations WHERE status='active' ORDER BY name").fetchall() if principal.can_manage_global else []
        html=[]
        for r in rows:
            scope='Device only'; actions=f"<a class='button' href='/blocked/{r['id']}'>Open</a>"
            if r['scoped_policy_id']:
                pdef=conn.execute('SELECT * FROM scoped_policies WHERE id=?',(r['scoped_policy_id'],)).fetchone()
                if pdef: scope=policy_scope_label(conn,pdef)
            if principal.can_approve and r['scoped_policy_id'] and r['scoped_active']:
                actions+=f"<form method='post' action='/admin/policies/{r['scoped_policy_id']}/disable'><button class='btn-warning'>Disable scoped block</button></form>"
            elif principal.can_approve and r['status']=='blocked' and r['policy_id']:
                actions+=f"<form method='post' action='/admin/blocked/{r['id']}/unblock'><button>Unblock device</button></form>"
            elif principal.can_approve and r['status']=='failed':
                actions+=f"<form method='post' action='/admin/blocked/{r['id']}/retry'><button>Retry</button></form>"
            changed=r['unblocked_at'] or r['blocked_at'] or r['created_at']
            note=(r['note'] or '').strip()
            html.append(f"<tr><td>{app_cell(r['product_name'],r['file_path'],'/blocked/%s' % r['id'])}<div class='muted'>{escape(short_publisher(r['publisher']))}</div></td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a><div class='muted'>{escape(r['organization_name'] or '')}</div></td><td>{escape(scope)}</td><td>{escape(r['blocked_by'] or 'System')}</td><td><span class='badge {block_status_class(r['status'])}'>{escape(block_status_label(r['status']))}</span><div class='muted'>{display_time(changed)}</div></td><td><span class='clip' title='{escape(note)}'>{escape(clipped(note,160))}</span></td><td><div class='action-stack'>{actions}</div></td></tr>")
    current=counts.get('blocked',0); in_progress=counts.get('blocking',0)+counts.get('unblocking',0); failed=counts.get('failed',0); unblocked=counts.get('unblocked',0)
    summary=f"<div class='grid'><div class='stat'><span class='stat-label'>Current Blocks</span><b>{current}</b><span class='trend'>Installed explicit deny rules</span></div><div class='stat'><span class='stat-label'>In Progress</span><b>{in_progress}</b><span class='trend'>Blocking or unblocking</span></div><div class='stat'><span class='stat-label'>Failed</span><b>{failed}</b><span class='trend'>Requires administrator review</span></div><div class='stat'><span class='stat-label'>Unblocked History</span><b>{unblocked}</b><span class='trend'>Previously removed deny rules</span></div></div>"
    status_options=''.join(f"<option value='{v}' {'selected' if block_status==v else ''}>{label}</option>" for v,label in [('active','Active / attention'),('blocked','Blocked'),('blocking','Blocking'),('unblocking','Unblocking'),('failed','Failed'),('unblocked','Unblocked history'),('all','All statuses')])
    scope_options=''.join(f"<option value='{v}' {'selected' if scope_type==v else ''}>{label}</option>" for v,label in [('', 'All scopes'),('device','Device only'),('scoped','Central scoped policies')])
    period_options=''.join(f"<option value='{v}' {'selected' if period==v else ''}>{label}</option>" for v,label in [(0,'All time'),(7,'Last 7 days'),(30,'Last 30 days'),(90,'Last 90 days'),(365,'Last 365 days')])
    sort_options=''.join(f"<option value='{v}' {'selected' if sort==v else ''}>{label}</option>" for v,label in [('newest','Newest first'),('oldest','Oldest first')])
    org_filter=''
    if principal.can_manage_global:
        org_options="<option value=''>All organizations</option>"+''.join(f"<option value='{o['id']}' {'selected' if organization_id==str(o['id']) else ''}>{escape(o['name'])}</option>" for o in orgs)
        org_filter=f"<div class='field'><label>Organization</label><select name='organization_id'>{org_options}</select></div>"
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Application, device, publisher, result'></div>{org_filter}<div class='field'><label>Status</label><select name='block_status'>{status_options}</select></div><div class='field'><label>Scope</label><select name='scope_type'>{scope_options}</select></div><div class='field'><label>Period</label><select name='period'>{period_options}</select></div><div class='field'><label>Sort</label><select name='sort'>{sort_options}</select></div><button class='btn-primary'>Filter</button><a href='/blocked'><button type='button'>Clear</button></a></form>"
    params_nav={'q':q,'block_status':block_status,'scope_type':scope_type,'organization_id':organization_id,'period':period,'sort':sort}
    body=("<div class='notice'>Device policy operation already in progress.</div>" if busy else '')+summary+f"<div class='section-head'><h2>Explicit Block Inventory & History</h2><span class='muted'>{total} match current filters</span></div><p class='muted'>Device-only and centrally scoped deny rules are shown together. Unblocked records remain available as history instead of disappearing from management view.</p>{filters}<div class='card'><table><tr><th>Application</th><th>Device</th><th>Scope</th><th>Initiated By</th><th>Status / Changed</th><th>Result</th><th>Action</th></tr>{''.join(html) or '<tr><td colspan=7><div class=empty>No explicit blocks match these filters.</div></td></tr>'}</table></div>{pager('/blocked',page_num,total,params_nav)}"
    return page('Explicit Blocks',body,principal,subtitle='Searchable current deny inventory plus historical block and unblock outcomes.',actions="<a class='button' href='/blocked-events'>Blocked Activity</a><a class='button' href='/reports/policies?period=30'>Policy Report</a>")


@app.get('/blocked/{block_id}', response_class=HTMLResponse)
def blocked_detail(block_id:int, principal:Principal=Depends(admin_auth)):
    with db() as conn:
        r=conn.execute("""SELECT b.*,d.hostname,d.organization_id,o.name organization_name,p.id scoped_policy_id,p.active scoped_active,p.name scoped_policy_name
            FROM blocked_applications b JOIN devices d ON d.id=b.device_id LEFT JOIN organizations o ON o.id=d.organization_id LEFT JOIN scoped_policies p ON p.id=b.policy_definition_id WHERE b.id=?""",(block_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Explicit block not found')
        require_org_access(principal,r['organization_id'])
        scope='Device only'
        if r['scoped_policy_id']:
            pdef=conn.execute('SELECT * FROM scoped_policies WHERE id=?',(r['scoped_policy_id'],)).fetchone()
            if pdef: scope=policy_scope_label(conn,pdef)
        request_row=conn.execute('SELECT * FROM approval_requests WHERE id=?',(r['source_request_id'],)).fetchone() if r['source_request_id'] else None
        if not request_row:
            request_row=conn.execute("SELECT * FROM approval_requests WHERE device_id=? AND lower(file_path)=lower(?) AND ABS(julianday(created_at)-julianday(?))<=7 ORDER BY ABS(julianday(created_at)-julianday(?)) ASC,id DESC LIMIT 1",(r['device_id'],r['file_path'],r['created_at'],r['created_at'])).fetchone()
        events=conn.execute("SELECT * FROM events WHERE device_id=? AND event_id=3077 AND lower(file_path)=lower(?) ORDER BY id DESC LIMIT 25",(r['device_id'],r['file_path'])).fetchall()
        event_count=conn.execute("SELECT COUNT(*) n FROM events WHERE device_id=? AND event_id=3077 AND lower(file_path)=lower(?)",(r['device_id'],r['file_path'])).fetchone()['n']
        actions=''
        if principal.can_approve and r['scoped_policy_id'] and r['scoped_active']:
            actions=f"<form method='post' action='/admin/policies/{r['scoped_policy_id']}/disable'><button class='btn-warning'>Disable scoped block</button></form>"
        elif principal.can_approve and r['status']=='blocked' and r['policy_id']:
            actions=f"<form method='post' action='/admin/blocked/{r['id']}/unblock'><button>Unblock device</button></form>"
        elif principal.can_approve and r['status']=='failed':
            actions=f"<form method='post' action='/admin/blocked/{r['id']}/retry'><button>Retry block</button></form>"
    request_html="<span class='muted'>No related approval request.</span>"
    if request_row:
        note=(request_row['decision_note'] or '').strip()
        request_html=f"<a href='/requests/{request_row['id']}'><b>Request #{request_row['id']}</b></a> <span class='badge {request_status_class(request_row['status'])}'>{escape(request_status_label(request_row['status']))}</span>"
        if note: request_html+=f"<div class='muted'>{escape(clipped(note,250))}</div>"
    event_rows=''.join(f"<tr><td>{display_time(e['occurred_at'] or e['received_at'])}</td><td><a href='/events/{e['id']}'>Event #{e['id']}</a></td><td>{escape(e['parent_path'] or '')}</td><td>{escape(e['file_version'] or '')}</td></tr>" for e in events)
    details=f"""<div class='panel'><div class='details-grid'>
      <div class='detail-item'><span class='muted'>Application</span><b>{escape(r['product_name'] or filename(r['file_path']))}</b></div>
      <div class='detail-item'><span class='muted'>Device</span><a href='/devices/{r['device_id']}'><b>{escape(r['hostname'])}</b></a><div class='muted'>{escape(r['organization_name'] or '')}</div></div>
      <div class='detail-item'><span class='muted'>Status</span><span class='badge {block_status_class(r['status'])}'>{escape(block_status_label(r['status']))}</span></div>
      <div class='detail-item'><span class='muted'>Scope</span><b>{escape(scope)}</b></div>
      <div class='detail-item'><span class='muted'>Initiated by</span><b>{escape(r['blocked_by'] or 'System')}</b></div>
      <div class='detail-item'><span class='muted'>Created</span><b>{display_time(r['created_at'])}</b></div>
      <div class='detail-item'><span class='muted'>Blocked</span><b>{display_time(r['blocked_at']) or 'Not completed'}</b></div>
      <div class='detail-item'><span class='muted'>Unblocked</span><b>{display_time(r['unblocked_at']) or '—'}</b><div class='muted'>{escape(r['unblocked_by'] or '')}</div></div>
      <div class='detail-item'><span class='muted'>Rule type</span><b>{escape(r['rule_type'] or '')}</b></div>
      <div class='detail-item'><span class='muted'>WDAC policy ID</span><code>{escape(r['policy_id'] or '')}</code></div>
    </div><div class='detail-item'><span class='muted'>Full path</span><code>{escape(r['file_path'])}</code></div><div class='detail-item'><span class='muted'>Publisher</span>{escape(r['publisher'] or '')}</div><div class='detail-item'><span class='muted'>SHA256</span><code>{escape(r['sha256'] or '')}</code></div><div class='detail-item'><span class='muted'>Latest result / note</span>{escape(r['note'] or '')}</div></div>"""
    related=f"<div class='section-head'><h2>Related Approval</h2></div><div class='panel'>{request_html}</div>"
    activity=f"<div class='section-head'><h2>Blocked Activity</h2><span class='muted'>{event_count} matching event{'s' if event_count!=1 else ''}</span></div><div class='card'><table><tr><th>Time</th><th>Event</th><th>Parent Process</th><th>Version</th></tr>{event_rows or '<tr><td colspan=4><div class=empty>No matching block events recorded.</div></td></tr>'}</table></div>"
    action_panel=f"<div class='panel'><h2 style='margin-top:0'>Management Action</h2><div class='actions'>{actions}</div></div>" if actions else ''
    return page(f'Explicit Block #{block_id}',details+related+action_panel+activity,principal,subtitle='Deny rule details, related approval history and matching blocked events.',actions="<a class='button' href='/blocked'>Back to Explicit Blocks</a><a class='button' href='/blocked-events'>Blocked Activity</a>")


@app.get('/commands', response_class=HTMLResponse)
def commands_page(q:str='', command_status:str='', page_num:int=Query(1,alias='page'), principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    with db() as conn:
        clause,params=visible_device_clause(principal,'d')
        where=[clause]; args=list(params)
        if command_status:
            where.append('c.status=?'); args.append(command_status)
        if q:
            term=f"%{q.lower()}%"
            where.append("(lower(d.hostname) LIKE ? OR lower(c.command_type) LIKE ? OR lower(COALESCE(c.result,'')) LIKE ?)")
            args += [term]*3
        where_sql=' AND '.join(where)
        total=conn.execute(f"SELECT COUNT(*) n FROM commands c JOIN devices d ON d.id=c.device_id WHERE {where_sql}",args).fetchone()['n']
        rows=conn.execute(f"SELECT c.*,d.hostname FROM commands c JOIN devices d ON d.id=c.device_id WHERE {where_sql} ORDER BY c.id DESC LIMIT ? OFFSET ?",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
    html=[]
    for r in rows:
        result=escape(r['result'] or '')
        result_html=f"<details><summary>View result</summary><code style='white-space:pre-wrap;word-break:break-word'>{result}</code></details>" if result else ''
        cls='badge-ok' if r['status']=='completed' else ('badge-bad' if r['status']=='failed' else 'badge-warn')
        html.append(f"<tr><td>{r['id']}</td><td><a href='/devices/{r['device_id']}'>{escape(r['hostname'])}</a></td><td>{escape(r['command_type'])}</td><td><span class='badge {cls}'>{escape(r['status'])}</span></td><td>{r['attempt_count'] or 0}</td><td>{display_time(r['created_at'])}</td><td>{display_time(r['started_at'])}</td><td>{display_time(r['completed_at'])}</td><td>{result_html}</td></tr>")
    status_opts=''.join(f"<option value='{v}' {'selected' if command_status==v else ''}>{label}</option>" for v,label in [('', 'All statuses'),('pending','Pending'),('processing','Processing'),('completed','Completed'),('failed','Failed'),('canceled','Canceled')])
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Device, command, result'></div><div class='field'><label>Status</label><select name='command_status'>{status_opts}</select></div><button class='btn-primary'>Filter</button><a href='/commands'><button type='button'>Clear</button></a></form>"
    return page('Command History',f"{filters}<div class='card'><table><tr><th>ID</th><th>Device</th><th>Command</th><th>Status</th><th>Attempts</th><th>Created</th><th>Started</th><th>Completed</th><th>Result</th></tr>{''.join(html) or '<tr><td colspan=8><div class=empty>No commands match these filters.</div></td></tr>'}</table></div>{pager('/commands',page_num,total,{'q':q,'command_status':command_status})}",principal,subtitle='Endpoint policy, update and lifecycle command execution history.',actions="<a class='button' href='/reports/commands'>Command Report</a><a class='button' href='/reports/commands.csv'>Export CSV</a>")


@app.get('/audit-log', response_class=HTMLResponse)
def audit_log_page(q:str='', page_num:int=Query(1,alias='page'), principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    with db() as conn:
        where=[]; args=[]
        if not principal.can_manage_global:
            where.append('a.organization_id=?'); args.append(principal.organization_id)
        if q:
            term=f"%{q.lower()}%"
            where.append("(lower(COALESCE(a.actor,'')) LIKE ? OR lower(a.action) LIKE ? OR lower(COALESCE(a.detail,'')) LIKE ? OR lower(COALESCE(d.hostname,'')) LIKE ?)")
            args += [term]*4
        where_sql='WHERE '+' AND '.join(where) if where else ''
        total=conn.execute(f"SELECT COUNT(*) n FROM audit_log a LEFT JOIN devices d ON d.id=a.device_id {where_sql}",args).fetchone()['n']
        rows=conn.execute(f"""SELECT a.*,d.hostname,o.name organization_name FROM audit_log a
            LEFT JOIN devices d ON d.id=a.device_id LEFT JOIN organizations o ON o.id=a.organization_id
            {where_sql} ORDER BY a.id DESC LIMIT ? OFFSET ?""",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
    html_parts=[]
    for r in rows:
        device_html = f"<a href='/devices/{r['device_id']}'>{escape(r['hostname'] or r['device_id'])}</a>" if r['device_id'] else ''
        html_parts.append(f"<tr><td class='nowrap'>{display_time(r['occurred_at'])}</td><td>{escape(r['actor'] or '')}</td><td>{escape((r['action'] or '').replace('_',' ').title())}</td><td>{escape(r['organization_name'] or '')}</td><td>{device_html}</td><td>{escape(r['object_type'] or '')}</td><td>{escape(r['detail'] or '')}</td></tr>")
    html=''.join(html_parts)
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Actor, action, device, detail'></div><button class='btn-primary'>Filter</button><a href='/audit-log'><button type='button'>Clear</button></a></form>"
    return page('Audit Log',f"{filters}<div class='card'><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Organization</th><th>Device</th><th>Object</th><th>Detail</th></tr>{html or '<tr><td colspan=7><div class=empty>No audit activity matches these filters.</div></td></tr>'}</table></div>{pager('/audit-log',page_num,total,{'q':q})}",principal,subtitle='Administrative, authentication and policy-management actions retained for accountability.',actions="<a class='button' href='/reports/audit'>Audit Report</a><a class='button' href='/reports/audit.csv'>Export CSV</a>")


@app.get('/policies', response_class=HTMLResponse)
def policies_page(q:str='',policy_action:str='',policy_status:str='',page_num:int=Query(1,alias='page'),principal:Principal=Depends(admin_auth)):
    page_num=max(1,page_num)
    with db() as conn:
        where=['deleted_at IS NULL']; args=[]
        if not principal.can_manage_global: where.append("(organization_id=? OR scope_type='global')"); args.append(principal.organization_id)
        if q:
            term=f"%{q.lower()}%"; where.append("(lower(name) LIKE ? OR lower(COALESCE(product_name,'')) LIKE ? OR lower(COALESCE(publisher,'')) LIKE ? OR lower(COALESCE(file_path,'')) LIKE ?)"); args += [term]*4
        if policy_action in {'allow','block'}: where.append('action=?'); args.append(policy_action)
        if policy_status=='active': where.append('active=1')
        elif policy_status=='disabled': where.append('active=0')
        ws=' AND '.join(where)
        total=conn.execute(f'SELECT COUNT(*) n FROM scoped_policies WHERE {ws}',args).fetchone()['n']
        rows=conn.execute(f"SELECT * FROM scoped_policies WHERE {ws} ORDER BY active DESC,CASE action WHEN 'block' THEN 0 ELSE 1 END,id DESC LIMIT ? OFFSET ?",args+[PAGE_SIZE,(page_num-1)*PAGE_SIZE]).fetchall()
        html=[]
        for r in rows:
            label=policy_scope_label(conn,r); action=''; can_manage=principal.can_manage_org and (principal.can_manage_global or r['organization_id']==principal.organization_id)
            if r['active'] and can_manage: action=f"<form method='post' action='/admin/policies/{r['id']}/disable'><button class='btn-warning'>Disable</button></form>"
            elif (not r['active']) and can_manage: action=f"<form method='post' action='/admin/policies/{r['id']}/delete' onsubmit=\"return confirm('Delete this disabled policy from the management view? Historical audit references are retained.');\"><button class='btn-danger'>Delete</button></form>"
            cls='badge-bad' if r['action']=='block' else 'badge-ok'; targets=len(scoped_policy_devices(conn,r)); status_cls='badge-ok' if r['active'] else ''
            appname=r['product_name'] or filename(r['file_path']) or r['name']; appsub='' if appname==r['name'] else f"<div class='muted'>{escape(r['name'])}</div>"
            html.append(f"<tr><td><div class='app-cell'><b>{escape(appname)}</b>{appsub}</div></td><td><span class='badge {cls}'>{escape(r['action'].upper())}</span></td><td>{escape(label)}<div class='muted'>{targets} target device(s)</div></td><td>{escape(r['identity_type'])}<div class='muted'>{escape(r['rule_type'] or '')}</div></td><td><div class='publisher-short' title='{escape(r['publisher'] or '')}'>{escape(short_publisher(r['publisher']))}</div></td><td><span class='badge {status_cls}'>{'Active' if r['active'] else 'Disabled'}</span><div class='muted'>{escape(r['created_by'] or '')}</div></td><td>{action}</td></tr>")
    act_opts=f"<option value=''>All actions</option><option value='allow' {'selected' if policy_action=='allow' else ''}>ALLOW</option><option value='block' {'selected' if policy_action=='block' else ''}>BLOCK</option>"
    st_opts=f"<option value=''>All statuses</option><option value='active' {'selected' if policy_status=='active' else ''}>Active</option><option value='disabled' {'selected' if policy_status=='disabled' else ''}>Disabled</option>"
    filters=f"<form class='filters' method='get'><div class='field'><label>Search</label><input name='q' value='{escape(q)}' placeholder='Application, policy or publisher'></div><div class='field'><label>Action</label><select name='policy_action'>{act_opts}</select></div><div class='field'><label>Status</label><select name='policy_status'>{st_opts}</select></div><button class='btn-primary'>Filter</button><a href='/policies'><button type='button'>Clear</button></a></form>"
    body="<div class='notice-info'><b>Policy precedence:</b> BLOCK always wins over ALLOW. Disable removes policy effect from endpoints; Delete removes a fully cleaned-up disabled policy from this view while retaining audit references.</div>"+filters+f"<div class='card'><table><tr><th>Application / Policy</th><th>Action</th><th>Scope</th><th>Identity</th><th>Publisher</th><th>Status</th><th></th></tr>{''.join(html) or '<tr><td colspan=7><div class=\"empty\">No policies match these filters.</div></td></tr>'}</table></div>{pager('/policies',page_num,total,{'q':q,'policy_action':policy_action,'policy_status':policy_status})}"
    return page('Application Policies',body,principal,subtitle='Central ALLOW and BLOCK policy inventory across device, group, organization and global scopes.',actions="<a class='button' href='/reports/policies'>Policy Report</a>")



def deployment_scope_label(conn: sqlite3.Connection, row: sqlite3.Row) -> str:
    st=row['scope_type']; sid=row['scope_id']
    if st=='global': return 'All organizations'
    if st=='organization':
        o=conn.execute('SELECT name FROM organizations WHERE id=?',(sid,)).fetchone(); return 'Organization: '+(o['name'] if o else str(sid))
    if st=='group':
        g=conn.execute('SELECT name FROM device_groups WHERE id=?',(sid,)).fetchone(); return 'Group: '+(g['name'] if g else str(sid))
    if st=='device':
        d=conn.execute('SELECT hostname FROM devices WHERE id=?',(sid,)).fetchone(); return 'Device: '+(d['hostname'] if d else str(sid))
    return st


@app.get('/server-updates', response_class=HTMLResponse)
def server_updates_page(principal: Principal = Depends(admin_auth)):
    if not principal.can_manage_global:
        raise HTTPException(status_code=403, detail='Global administrator permission required.')
    current = app.version
    release = None
    release_error = ''
    try:
        release = fetch_latest_release(GITHUB_REPO, token=GITHUB_TOKEN or None, api_base=GITHUB_API_BASE)
    except Exception as exc:
        release_error = str(exc)

    active = _server_update_unit_active()
    log_tail = _server_update_log_tail()
    imported = False
    matching_release_id = None
    if release:
        with db() as conn:
            row = conn.execute(
                "SELECT id FROM agent_releases WHERE version=? AND channel='stable' AND deleted_at IS NULL",
                (release.version,),
            ).fetchone()
            if row:
                imported = True
                matching_release_id = row['id']

    if release:
        assets = server_update_asset_status(release)
        all_assets = all(assets.values())
        if version_key(release.version) > version_key(current):
            status_text, status_badge = 'Update available', 'badge-warn'
        elif version_key(release.version) == version_key(current):
            status_text, status_badge = 'Up to date', 'badge-ok'
        else:
            status_text, status_badge = 'Local server is newer than GitHub latest', 'badge-info'
        names = server_update_asset_names(release.version)
        asset_rows = ''.join(
            f"<tr><td>{escape(names[key])}</td><td><span class='badge {'badge-ok' if ok else 'badge-bad'}'>{'Available' if ok else 'Missing'}</span></td></tr>"
            for key, ok in assets.items()
        )
        notes = escape(release.notes or 'No release notes were provided.')
        release_link = f"<a href='{escape(release.html_url)}' target='_blank' rel='noopener'>Open GitHub Release</a>" if release.html_url else ''
        imported_text = f"Imported as agent release #{matching_release_id}" if imported else 'Not imported yet; it will be imported automatically after a successful server update.'
        install_disabled = ' disabled' if active or not all_assets or version_key(release.version) <= version_key(current) else ''
        install_help = 'An update is already running.' if active else ('All six release assets are required before installation.' if not all_assets else 'The server restarts during installation. Refresh this page after about a minute.')
        release_panel = f"""
        <div class='grid'>
          <div class='stat'><span class='stat-label'>Current Server</span><b>{escape(current)}</b><span class='trend'>Installed</span></div>
          <div class='stat'><span class='stat-label'>Latest GitHub Release</span><b>{escape(release.version)}</b><span class='trend'>{escape(release.published_at or 'Publication time unavailable')}</span></div>
          <div class='stat'><span class='stat-label'>Status</span><b style='font-size:18px'><span class='badge {status_badge}'>{status_text}</span></b><span class='trend'>{release_link}</span></div>
          <div class='stat'><span class='stat-label'>Matching Agent</span><b style='font-size:18px'>{'Ready' if imported else 'Pending'}</b><span class='trend'>{escape(imported_text)}</span></div>
        </div>
        <div class='grid-2' style='margin-top:18px'>
          <div class='panel'><h2 style='margin-top:0'>Release Assets</h2><div class='card'><table><thead><tr><th>Asset</th><th>Status</th></tr></thead><tbody>{asset_rows}</tbody></table></div></div>
          <div class='panel'><h2 style='margin-top:0'>Release Notes</h2><div class='callout' style='white-space:pre-wrap'>{notes}</div></div>
        </div>
        <div class='panel'><h2 style='margin-top:0'>Install Server Update</h2><p class='muted'>{escape(install_help)}</p>
          <form method='post' action='/admin/server-updates/install'><button class='btn-primary'{install_disabled}>Install {escape(release.version)}</button></form>
        </div>
        """
    else:
        release_panel = f"<div class='notice-warn'><b>Unable to check GitHub Releases.</b><br>{escape(release_error or 'Unknown GitHub error')}</div><div class='panel'><b>Repository:</b> {escape(GITHUB_REPO)}<br><span class='muted'>Confirm the repository has a published release and configure APPCONTROL_GITHUB_TOKEN if it is private.</span></div>"

    log_panel = ''
    if active or log_tail:
        state = 'Update is running' if active else 'Last update output'
        badge = 'badge-warn' if active else 'badge-info'
        state_label = 'Running' if active else 'Idle'
        log_panel = f"<div class='panel'><div class='section-head' style='margin-top:0'><h2>{state}</h2><span class='badge {badge}'>{state_label}</span></div><pre style='white-space:pre-wrap;max-height:420px;overflow:auto;background:#101828;color:#e5e7eb;padding:13px;border-radius:8px'>{escape(log_tail or 'Updater started. Waiting for output...')}</pre></div>"
    return page(
        'Server Updates',
        release_panel + log_panel,
        principal,
        subtitle=f'GitHub release status for {GITHUB_REPO}. Server installation remains an explicit administrator action.',
    )


@app.post('/admin/server-updates/install')
def install_server_update(principal: Principal = Depends(admin_auth)):
    if not principal.can_manage_global:
        raise HTTPException(status_code=403, detail='Global administrator permission required.')
    try:
        result = _launch_server_update()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    with db() as conn:
        audit(
            conn,
            principal.username,
            'server_update_started',
            object_type='server_update',
            detail=result or str(SERVER_UPDATE_SCRIPT),
        )
    return RedirectResponse('/server-updates', status_code=303)


@app.get('/downloads/installer/latest')
def download_latest_installer():
    with db() as conn:
        rows=conn.execute("SELECT * FROM agent_releases WHERE active=1 AND deleted_at IS NULL AND channel='stable' AND installer_file_path IS NOT NULL").fetchall()
        if not rows: raise HTTPException(status_code=404,detail='No stable AppControl Manager installer has been published.')
        release=max(rows,key=lambda r: version_key(r['version']))
    path=Path(release['installer_file_path'])
    if not path.is_file(): raise HTTPException(status_code=404,detail='Installer file is missing on the server.')
    return FileResponse(path,media_type='application/vnd.microsoft.portable-executable',filename=release['installer_file_name'])


@app.get('/downloads/installer/{release_id}')
def download_installer(release_id:int,principal:Principal=Depends(admin_auth)):
    with db() as conn:
        r=conn.execute('SELECT * FROM agent_releases WHERE id=? AND deleted_at IS NULL',(release_id,)).fetchone()
        if not r or not r['installer_file_path']: raise HTTPException(status_code=404,detail='Installer not found')
    path=Path(r['installer_file_path'])
    if not path.is_file(): raise HTTPException(status_code=404,detail='Installer file is missing on the server.')
    return FileResponse(path,media_type='application/vnd.microsoft.portable-executable',filename=r['installer_file_name'])


@app.get('/agent-updates', response_class=HTMLResponse)
def agent_updates_page(principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        releases=conn.execute('SELECT * FROM agent_releases WHERE deleted_at IS NULL ORDER BY id DESC').fetchall()
        if principal.can_manage_global:
            deployments=conn.execute('SELECT * FROM agent_deployments ORDER BY id DESC').fetchall(); orgs=conn.execute("SELECT * FROM organizations WHERE status='active' ORDER BY name").fetchall(); groups=conn.execute("SELECT g.*,o.name organization_name FROM device_groups g JOIN organizations o ON o.id=g.organization_id ORDER BY o.name,g.name").fetchall(); devices=conn.execute('SELECT * FROM devices ORDER BY hostname').fetchall()
        else:
            deployments=conn.execute("SELECT * FROM agent_deployments WHERE organization_id=? OR (scope_type='device' AND scope_id IN (SELECT id FROM devices WHERE organization_id=?)) ORDER BY id DESC",(principal.organization_id,principal.organization_id)).fetchall(); orgs=conn.execute('SELECT * FROM organizations WHERE id=?',(principal.organization_id,)).fetchall(); groups=conn.execute('SELECT g.*,o.name organization_name FROM device_groups g JOIN organizations o ON o.id=g.organization_id WHERE g.organization_id=? ORDER BY g.name',(principal.organization_id,)).fetchall(); devices=conn.execute('SELECT * FROM devices WHERE organization_id=? ORDER BY hostname',(principal.organization_id,)).fetchall()
        # Version distribution and deployment health summary.
        version_counts={}
        for d in devices: version_counts[d['agent_version'] or 'Unknown']=version_counts.get(d['agent_version'] or 'Unknown',0)+1
        current=sum(1 for d in devices if not d['desired_agent_version'] or d['desired_agent_version']==d['agent_version'])
        pending=sum(1 for d in devices if d['desired_agent_version'] and d['desired_agent_version']!=d['agent_version'] and (d['update_status'] or '').lower() not in {'failed','rolled_back'})
        failed=sum(1 for d in devices if (d['update_status'] or '').lower() in {'failed','rolled_back'})
    upload=''
    if principal.can_manage_global:
        upload="""<div class='panel'><div class='section-head' style='margin-top:0'><h2>Publish Agent Release</h2></div><form method='post' action='/admin/agent-releases' enctype='multipart/form-data'><div class='grid-3'><div class='field'><label>Version</label><input name='version' placeholder='0.11.2' required></div><div class='field'><label>Release Channel</label><select name='channel'><option value='stable'>Stable</option><option value='beta'>Beta</option></select></div><div class='field'><label>Release Notes</label><input name='notes' placeholder='What changed in this release'></div></div><div class='grid-2'><div class='field'><label>Agent Update Package (.zip)</label><input type='file' name='package' accept='.zip' required></div><div class='field'><label>Single-file Installer (.exe, optional)</label><input type='file' name='installer' accept='.exe'></div></div><button class='btn-primary'>Upload and Validate Release</button></form><p class='muted'>Packages are validated against agent-manifest.json and stored SHA256 before they are eligible for deployment.</p></div>"""
    release_options=["<option value='channel:stable'>Latest Stable</option>","<option value='channel:beta'>Latest Beta</option>"]+[f"<option value='release:{r['id']}'>Pinned {escape(r['version'])} ({escape(r['channel'])})</option>" for r in releases if r['active']]
    scope_options=[]
    if principal.can_manage_global: scope_options.append("<option value='global:'>All organizations</option>")
    for o in orgs: scope_options.append(f"<option value='organization:{o['id']}'>Organization: {escape(o['name'])}</option>")
    for g in groups: scope_options.append(f"<option value='group:{g['id']}'>Group: {escape(g['organization_name'])} / {escape(g['name'])}</option>")
    # Device targeting is useful for canary/testing overrides.
    for d in devices[:1000]: scope_options.append(f"<option value='device:{escape(d['id'])}'>Device: {escape(d['hostname'])}</option>")
    deploy_form=f"""<div class='panel'><h2 style='margin-top:0'>Automatic Agent Update Policy</h2><p class='muted'>Create an ongoing update rule. More specific rules override broader rules: Device → Group → Organization → Global.</p><form method='post' action='/admin/agent-deployments'><div class='grid-3'><div class='field'><label>Update Policy</label><select name='release_target'>{''.join(release_options)}</select></div><div class='field'><label>Apply To</label><select name='scope_target'>{''.join(scope_options)}</select></div><div class='field'><label>Rollout</label><select name='rollout_percent'><option value='10'>10% canary</option><option value='25'>25% staged</option><option value='50'>50% staged</option><option value='100' selected>100%</option></select></div></div><button class='btn-primary'>Create Update Policy</button></form></div>"""
    rr=[]
    for r in releases:
        action=''
        if principal.can_manage_global:
            toggle=f"<form method='post' action='/admin/agent-releases/{r['id']}/toggle'><button>{'Disable' if r['active'] else 'Enable'}</button></form>"; delete='' if r['active'] else f"<form method='post' action='/admin/agent-releases/{r['id']}/delete' onsubmit=\"return confirm('Delete the stored agent package and installer for version {escape(r['version'])}? This cannot be undone.');\"><button class='btn-danger'>Delete Files</button></form>"; action=f"<div class='actions'>{toggle}{delete}</div>"
        installer_link=(f"<a href='/downloads/installer/{r['id']}'>Download installer</a>" if r['installer_file_path'] else '<span class=muted>Not uploaded</span>')
        channel_cls='badge-info' if r['channel']=='beta' else 'badge-ok'; status_cls='badge-ok' if r['active'] else ''
        rr.append(f"<tr><td><b>{escape(r['version'])}</b><div class='muted'>{escape(r['notes'] or '')}</div></td><td><span class='badge {channel_cls}'>{escape(r['channel'].title())}</span></td><td><code>{escape(r['sha256'][:16])}…</code><div class='muted'>{r['size_bytes']//1024//1024} MB</div></td><td>{installer_link}</td><td><span class='badge {status_cls}'>{'Active' if r['active'] else 'Disabled'}</span></td><td>{display_time(r['created_at'])}</td><td>{action}</td></tr>")
    dr=[]
    with db() as conn:
        for d in deployments:
            rel=release_for_deployment(conn,d); target=(f"Latest {(d['channel'] or 'stable').title()}" if not d['release_id'] else (rel['version'] if rel else 'Missing release')); scope=deployment_scope_label(conn,d); act=f"<form method='post' action='/admin/agent-deployments/{d['id']}/toggle'><button>{'Pause' if d['active'] else 'Resume'}</button></form>"; dr.append(f"<tr><td><b>{escape(target)}</b></td><td>{escape(scope)}</td><td>{d['rollout_percent']}%</td><td><span class='badge {'badge-ok' if d['active'] else ''}'>{'Active' if d['active'] else 'Paused'}</span></td><td>{display_time(d['created_at'])}</td><td>{act}</td></tr>")
    max_ver=max(version_counts.values() or [1]); verbar=''.join(f"<div class='bar-row'><span>{escape(ver)}</span><div class='bar-track'><div class='bar-fill' style='width:{round(n*100/max_ver)}%'></div></div><b>{n}</b></div>" for ver,n in sorted(version_counts.items(),key=lambda x:x[1],reverse=True)[:10])
    summary=f"<div class='grid'><div class='stat'><span class='stat-label'>Managed Devices</span><b>{len(devices)}</b></div><div class='stat'><span class='stat-label'>At Desired Version</span><b>{current}</b></div><div class='stat'><span class='stat-label'>Pending Update</span><b>{pending}</b></div><div class='stat'><span class='stat-label'>Failed / Rolled Back</span><b>{failed}</b></div><div class='stat'><span class='stat-label'>Published Releases</span><b>{len(releases)}</b></div></div>"
    health=f"<div class='grid-2'><div><div class='section-head'><h2>Version Distribution</h2></div><div class='panel'><div class='bar-list'>{verbar or '<div class=empty>No agent version data.</div>'}</div></div></div><div><div class='section-head'><h2>Deployment Model</h2></div><div class='panel'><div class='metric-row'><span>Precedence</span><b>Device → Group → Organization → Global</b></div><div class='metric-row'><span>Stable channel</span><span>Production rollout</span></div><div class='metric-row'><span>Beta channel</span><span>Canary / test devices</span></div><div class='metric-row'><span>Staged rollout</span><span>10% / 25% / 50% / 100%</span></div></div></div></div>"
    body=summary+health+deploy_form+upload+f"<div class='section-head'><h2>Published Releases</h2></div><div class='card'><table><tr><th>Release</th><th>Channel</th><th>Package</th><th>Installer</th><th>Status</th><th>Uploaded</th><th>Actions</th></tr>{''.join(rr) or '<tr><td colspan=7><div class=empty>No releases uploaded.</div></td></tr>'}</table></div><div class='section-head'><h2>Automatic Update Policies</h2></div><div class='card'><table><tr><th>Target Release</th><th>Scope</th><th>Rollout</th><th>Status</th><th>Created</th><th>Actions</th></tr>{''.join(dr) or '<tr><td colspan=6><div class=empty>No automatic update policies.</div></td></tr>'}</table></div>"
    return page('Agent Updates',body,principal,subtitle='Publish agent releases, define Stable/Beta rollout policies and monitor deployment compliance.',actions="<a class='button' href='/reports/agent-updates'>Update Compliance Report</a>")


@app.post('/admin/agent-releases')
async def upload_agent_release(version:str=Form(...),channel:str=Form('stable'),notes:str=Form(''),package:UploadFile=File(...),installer:Optional[UploadFile]=File(None),principal:Principal=Depends(admin_auth)):
    if not principal.can_manage_global: raise HTTPException(status_code=403,detail='Global administrator permission required.')
    version=version.strip(); channel=channel.strip().lower()
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?',version): raise HTTPException(status_code=400,detail='Invalid version format.')
    if channel not in {'stable','beta'}: raise HTTPException(status_code=400,detail='Channel must be stable or beta.')
    RELEASE_DIR.mkdir(parents=True,exist_ok=True)
    file_name=f"AppControlManager-Agent-{version}-win-x64.zip"; safe=f"AppControlManager-Agent-{version}-{channel}-win-x64.zip"; temp=RELEASE_DIR/(safe+'.upload')
    digest=hashlib.sha256(); size=0
    with temp.open('wb') as out:
        while True:
            chunk=await package.read(1024*1024)
            if not chunk: break
            size+=len(chunk)
            if size>750*1024*1024:
                out.close(); temp.unlink(missing_ok=True); raise HTTPException(status_code=413,detail='Agent package exceeds 750 MB.')
            digest.update(chunk); out.write(chunk)
    try: validate_agent_package(temp,version)
    except ValueError as exc: temp.unlink(missing_ok=True); raise HTTPException(status_code=400,detail=str(exc))
    with db() as conn:
        if conn.execute('SELECT id FROM agent_releases WHERE version=? AND channel=? AND deleted_at IS NULL',(version,channel)).fetchone():
            temp.unlink(missing_ok=True)
            raise HTTPException(status_code=409,detail='That version/channel already exists.')
    final=RELEASE_DIR/safe
    if final.exists(): final.unlink()
    temp.replace(final)
    installer_name=installer_path=installer_hash=None; installer_size=None
    if installer and installer.filename:
        installer_name=f"AppControlManager-Installer-{version}.exe"; ipath=RELEASE_DIR/f"AppControlManager-Installer-{version}-{channel}.exe"; itemp=RELEASE_DIR/(f"AppControlManager-Installer-{version}-{channel}.exe.upload")
        ih=hashlib.sha256(); isize=0
        with itemp.open('wb') as out:
            while True:
                chunk=await installer.read(1024*1024)
                if not chunk: break
                isize+=len(chunk)
                if isize>750*1024*1024:
                    out.close(); itemp.unlink(missing_ok=True); final.unlink(missing_ok=True); raise HTTPException(status_code=413,detail='Installer exceeds 750 MB.')
                ih.update(chunk); out.write(chunk)
        if ipath.exists(): ipath.unlink()
        itemp.replace(ipath); installer_path=str(ipath); installer_hash=ih.hexdigest().upper(); installer_size=isize
    with db() as conn:
        if conn.execute('SELECT id FROM agent_releases WHERE version=? AND channel=? AND deleted_at IS NULL',(version,channel)).fetchone():
            # A concurrent upload won the race after our pre-check. Do not remove the established
            # release files; leave this rare case for the administrator to retry with another version.
            raise HTTPException(status_code=409,detail='That version/channel already exists.')
        cur=conn.execute('INSERT INTO agent_releases(version,channel,file_name,file_path,sha256,size_bytes,notes,active,created_at,created_by,installer_file_name,installer_file_path,installer_sha256,installer_size_bytes) VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?)',(version,channel,file_name,str(final),digest.hexdigest().upper(),size,notes.strip(),utcnow(),principal.username,installer_name,installer_path,installer_hash,installer_size))
        audit(conn,principal.username,'agent_release_uploaded',object_type='agent_release',object_id=cur.lastrowid,detail=f'{version} {channel}')
        refresh_all_device_update_targets(conn)
    return RedirectResponse('/agent-updates',status_code=303)


@app.post('/admin/agent-releases/{release_id}/toggle')
def toggle_agent_release(release_id:int,principal:Principal=Depends(admin_auth)):
    if not principal.can_manage_global: raise HTTPException(status_code=403,detail='Global administrator permission required.')
    with db() as conn:
        r=conn.execute('SELECT * FROM agent_releases WHERE id=? AND deleted_at IS NULL',(release_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Release not found')
        new_active=0 if r['active'] else 1
        conn.execute('UPDATE agent_releases SET active=? WHERE id=?',(new_active,release_id))
        if not new_active:
            cancel_pending_agent_updates(conn,release_id=release_id,reason=f'Agent release {r["version"]} was disabled before endpoint processing.')
        audit(conn,principal.username,'agent_release_toggled',object_type='agent_release',object_id=release_id,detail='disabled' if r['active'] else 'enabled')
        refresh_all_device_update_targets(conn)
    return RedirectResponse('/agent-updates',status_code=303)


@app.post('/admin/agent-releases/{release_id}/delete')
def delete_agent_release(release_id:int, principal:Principal=Depends(admin_auth)):
    if not principal.can_manage_global:
        raise HTTPException(status_code=403,detail='Global administrator permission required.')
    with db() as conn:
        r=conn.execute('SELECT * FROM agent_releases WHERE id=? AND deleted_at IS NULL',(release_id,)).fetchone()
        if not r:
            raise HTTPException(status_code=404,detail='Release not found')
        if r['active']:
            raise HTTPException(status_code=400,detail='Disable the release before deleting its stored files.')
        active_deployments=conn.execute('SELECT COUNT(*) n FROM agent_deployments WHERE release_id=? AND active=1',(release_id,)).fetchone()['n']
        active_commands=0
        for row in conn.execute("SELECT payload FROM commands WHERE command_type='update_agent' AND status IN ('pending','processing')").fetchall():
            try:
                if int(json.loads(row['payload'] or '{}').get('release_id') or 0)==release_id:
                    active_commands += 1
            except Exception:
                pass
        if active_deployments or active_commands:
            raise HTTPException(status_code=409,detail='This release is still referenced by an active deployment or endpoint update. Pause/remove the deployment and wait for active updates to finish first.')
        removed=[]
        for key in ('file_path','installer_file_path'):
            value=r[key]
            if not value:
                continue
            path=Path(value)
            try:
                if path.is_file():
                    path.unlink()
                    removed.append(str(path))
            except OSError as exc:
                raise HTTPException(status_code=500,detail=f'Could not remove {path}: {exc}')
        conn.execute('DELETE FROM agent_deployments WHERE release_id=? AND active=0',(release_id,))
        conn.execute("UPDATE agent_releases SET deleted_at=?,deleted_by=?,file_path='',installer_file_path=NULL WHERE id=?",(utcnow(),principal.username,release_id))
        audit(conn,principal.username,'agent_release_deleted',object_type='agent_release',object_id=release_id,detail=f"{r['version']} {r['channel']}; files removed={len(removed)}")
        refresh_all_device_update_targets(conn)
    return RedirectResponse('/agent-updates',status_code=303)


@app.post('/admin/agent-deployments')
def create_agent_deployment(release_target:str=Form(...),scope_target:str=Form(...),rollout_percent:int=Form(100),principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    try: rkind,rvalue=release_target.split(':',1); skind,svalue=scope_target.split(':',1)
    except ValueError: raise HTTPException(status_code=400,detail='Invalid deployment target.')
    if skind not in {'global','organization','group'}: raise HTTPException(status_code=400,detail='Invalid deployment scope.')
    rollout_percent=max(1,min(int(rollout_percent),100))
    with db() as conn:
        org_id=None
        if skind=='global':
            if not principal.can_manage_global: raise HTTPException(status_code=403,detail='Only global administrators can deploy globally.')
            svalue=''
        elif skind=='organization':
            o=conn.execute('SELECT id FROM organizations WHERE id=?',(svalue,)).fetchone()
            if not o: raise HTTPException(status_code=404,detail='Organization not found')
            require_org_access(principal,o['id']); org_id=o['id']
        else:
            g=conn.execute('SELECT * FROM device_groups WHERE id=?',(svalue,)).fetchone()
            if not g: raise HTTPException(status_code=404,detail='Group not found')
            require_org_access(principal,g['organization_id']); org_id=g['organization_id']
        release_id=None; channel=None
        if rkind=='release':
            r=conn.execute('SELECT * FROM agent_releases WHERE id=? AND active=1 AND deleted_at IS NULL',(rvalue,)).fetchone()
            if not r: raise HTTPException(status_code=404,detail='Release not found')
            release_id=r['id']
        elif rkind=='channel' and rvalue in {'stable','beta'}: channel=rvalue
        else: raise HTTPException(status_code=400,detail='Invalid release target.')
        cur=conn.execute('INSERT INTO agent_deployments(release_id,channel,scope_type,scope_id,organization_id,rollout_percent,active,created_at,created_by) VALUES(?,?,?,?,?,?,1,?,?)',(release_id,channel,skind,svalue or None,org_id,rollout_percent,utcnow(),principal.username))
        audit(conn,principal.username,'agent_deployment_created',organization_id=org_id,object_type='agent_deployment',object_id=cur.lastrowid,detail=f'{release_target} -> {scope_target} @ {rollout_percent}%')
        refresh_all_device_update_targets(conn)
    return RedirectResponse('/agent-updates',status_code=303)


@app.post('/admin/agent-deployments/{deployment_id}/toggle')
def toggle_agent_deployment(deployment_id:int,principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        d=conn.execute('SELECT * FROM agent_deployments WHERE id=?',(deployment_id,)).fetchone()
        if not d: raise HTTPException(status_code=404,detail='Deployment not found')
        if d['scope_type']=='global' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Global administrator permission required.')
        if d['organization_id']: require_org_access(principal,d['organization_id'])
        active=0 if d['active'] else 1
        conn.execute('UPDATE agent_deployments SET active=?,disabled_at=?,disabled_by=? WHERE id=?',(active,None if active else utcnow(),None if active else principal.username,deployment_id))
        if not active:
            cancel_pending_agent_updates(conn,deployment_id=deployment_id,reason='Agent deployment was paused before endpoint processing.')
        audit(conn,principal.username,'agent_deployment_toggled',organization_id=d['organization_id'],object_type='agent_deployment',object_id=deployment_id,detail='resumed' if active else 'paused')
        refresh_all_device_update_targets(conn)
    return RedirectResponse('/agent-updates',status_code=303)


@app.post('/admin/devices/{device_id}/agent-update')
def device_agent_update(device_id:str,release_id:int=Form(...),principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        d=conn.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not d: raise HTTPException(status_code=404,detail='Device not found')
        require_org_access(principal,d['organization_id'])
        r=conn.execute('SELECT * FROM agent_releases WHERE id=? AND active=1 AND deleted_at IS NULL',(release_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Release not found')
        # Replace older active device-specific deployments so the newest manual target wins cleanly.
        conn.execute("UPDATE agent_deployments SET active=0,disabled_at=?,disabled_by=? WHERE scope_type='device' AND scope_id=? AND active=1",(utcnow(),principal.username,device_id))
        cur=conn.execute("INSERT INTO agent_deployments(release_id,scope_type,scope_id,organization_id,rollout_percent,active,created_at,created_by) VALUES(?,'device',?,?,100,1,?,?)",(release_id,device_id,d['organization_id'],utcnow(),principal.username))
        conn.execute("UPDATE devices SET update_status=NULL,update_result=NULL WHERE id=?",(device_id,))
        audit(conn,principal.username,'agent_device_update_assigned',organization_id=d['organization_id'],device_id=device_id,object_type='agent_deployment',object_id=cur.lastrowid,detail=r['version'])
        refresh_device_update_target(conn,device_id)
    return RedirectResponse(f'/devices/{device_id}',status_code=303)


@app.post('/admin/devices/{device_id}/uninstall')
def uninstall_device_agent(device_id:str, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        d=conn.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not d:
            raise HTTPException(status_code=404,detail='Device not found')
        require_org_access(principal,d['organization_id'])
        if not version_at_least(d['agent_version'],'0.11.0'):
            raise HTTPException(status_code=409,detail='Remote uninstall requires AppControl Manager agent 0.11.0 or later. Update this endpoint first.')
        if active_device_command(conn,device_id):
            raise HTTPException(status_code=409,detail='Another endpoint command is already pending or processing. Wait for it to finish before uninstalling the agent.')
        conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",(device_id,'uninstall_agent',json.dumps({'requested_by':principal.username}),'pending',utcnow()))
        conn.execute("UPDATE devices SET offboard_status='queued',offboard_result=?,offboard_requested_at=?,offboard_completed_at=NULL WHERE id=?",('Remote uninstall queued. Waiting for the endpoint.',utcnow(),device_id))
        audit(conn,principal.username,'device_uninstall_queued',organization_id=d['organization_id'],device_id=device_id,object_type='device',object_id=device_id,detail=d['hostname'])
    return RedirectResponse(f'/devices/{device_id}',status_code=303)


@app.post('/admin/devices/{device_id}/delete')
def delete_device_record(device_id:str, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        d=conn.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not d:
            raise HTTPException(status_code=404,detail='Device not found')
        require_org_access(principal,d['organization_id'])
        allowed,reason=device_record_can_be_deleted(d)
        if not allowed:
            raise HTTPException(status_code=409,detail=reason)
        active=active_device_command(conn,device_id)
        if active:
            raise HTTPException(status_code=409,detail='This device still has a pending or processing command. Wait for it to finish before deleting the server record.')
        hostname=d['hostname']; org_id=d['organization_id']
        audit(conn,principal.username,'device_record_deleted',organization_id=org_id,object_type='device',object_id=device_id,detail=f'{hostname}; {reason}')
        purge_device_record(conn,device_id)
    return RedirectResponse('/devices',status_code=303)


@app.get('/organizations', response_class=HTMLResponse)
def organizations_page(principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        if principal.can_manage_global:
            orgs=conn.execute("SELECT o.*,(SELECT COUNT(*) FROM devices d WHERE d.organization_id=o.id) device_count FROM organizations o ORDER BY o.name").fetchall()
        else:
            orgs=conn.execute("SELECT o.*,(SELECT COUNT(*) FROM devices d WHERE d.organization_id=o.id) device_count FROM organizations o WHERE o.id=?",(principal.organization_id,)).fetchall()
        groups=conn.execute("SELECT g.*,o.name organization_name FROM device_groups g JOIN organizations o ON o.id=g.organization_id " + ("ORDER BY o.name,g.name" if principal.can_manage_global else "WHERE g.organization_id=? ORDER BY g.name"), [] if principal.can_manage_global else [principal.organization_id]).fetchall()
        keys=conn.execute("SELECT k.*,o.name organization_name FROM enrollment_keys k JOIN organizations o ON o.id=k.organization_id " + ("ORDER BY o.name,k.id DESC" if principal.can_manage_global else "WHERE k.organization_id=? ORDER BY k.id DESC"), [] if principal.can_manage_global else [principal.organization_id]).fetchall()
    create_org=''
    if principal.can_manage_global:
        create_org="<div class='panel'><h2>Create organization</h2><form class='actions' method='post' action='/admin/organizations'><input name='name' placeholder='Organization name' required><button class='btn-primary'>Create</button></form></div>"
    org_rows=''.join(f"<tr><td>{escape(o['name'])}</td><td>{escape(o['slug'])}</td><td>{o['device_count']}</td><td>{escape(o['status'])}</td><td><form method='post' action='/admin/organizations/{o['id']}/keys'><input name='name' value='Agent enrollment' required><button>Create enrollment token</button></form><form method='post' action='/admin/organizations/{o['id']}/groups'><input name='name' placeholder='New device group' required><button>Create group</button></form></td></tr>" for o in orgs)
    group_rows=''.join(f"<tr><td>{escape(g['organization_name'])}</td><td>{escape(g['name'])}</td><td>{escape(g['description'] or '')}</td></tr>" for g in groups)
    key_rows_parts=[]
    for k in keys:
        key_action = '' if not k['active'] else f"<form method='post' action='/admin/enrollment-keys/{k['id']}/disable'><button class='btn-warning'>Disable</button></form>"
        if k['token_value']:
            token_id=f"enrollment-token-{k['id']}"
            copy_button=f"<button type='button' class='copy-btn' onclick=\"acmCopy('{token_id}',this)\">Copy</button>" if k['active'] else ''
            token_html=f"<div class='copy-wrap'><code id='{token_id}' data-copy='{escape(k['token_value'])}'>{escape(k['token_value'])}</code>{copy_button}</div>"
        else:
            token_html=f"<code>{escape(k['token_prefix'] or '')}...</code><div class='muted'>Full token was not retained by releases before 0.12.5. Create a new token to make it reusable/copyable here.</div>"
        key_rows_parts.append(f"<tr><td>{escape(k['organization_name'])}</td><td>{escape(k['name'])}</td><td>{token_html}</td><td>{'Active' if k['active'] else 'Disabled'}</td><td>{escape(k['last_used_at'] or '')}</td><td>{key_action}</td></tr>")
    key_rows=''.join(key_rows_parts)
    body=create_org+f"<h2>Organizations</h2><div class='card'><table><tr><th>Name</th><th>Slug</th><th>Devices</th><th>Status</th><th>Management</th></tr>{org_rows}</table></div><h2>Device Groups</h2><div class='card'><table><tr><th>Organization</th><th>Name</th><th>Description</th></tr>{group_rows or '<tr><td colspan=3>No groups.</td></tr>'}</table></div><h2>Enrollment Tokens</h2><div class='notice-info'><b>Deployment tokens are reusable.</b> Active tokens remain valid until you disable them, making them suitable for VSA X and other automated onboarding workflows.</div><div class='card'><table><tr><th>Organization</th><th>Name</th><th>Enrollment token</th><th>Status</th><th>Last used</th><th>Action</th></tr>{key_rows or '<tr><td colspan=6>No enrollment tokens.</td></tr>'}</table></div>"
    return page('Organizations & Device Groups',body,principal)


@app.get('/users', response_class=HTMLResponse)
def users_page(principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        if principal.can_manage_global:
            users=conn.execute("SELECT u.*,o.name organization_name FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.deleted_at IS NULL ORDER BY u.username").fetchall()
            orgs=conn.execute("SELECT * FROM organizations WHERE status='active' ORDER BY name").fetchall()
        else:
            users=conn.execute("SELECT u.*,o.name organization_name FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.organization_id=? AND u.deleted_at IS NULL ORDER BY u.username",(principal.organization_id,)).fetchall()
            orgs=conn.execute("SELECT * FROM organizations WHERE id=?",(principal.organization_id,)).fetchall()
    roles=['org_admin','approver','read_only'] + (['global_admin'] if principal.can_manage_global else [])
    orgopts="<option value=''>Global / none</option>" if principal.can_manage_global else ''
    orgopts+=''.join(f"<option value='{o['id']}'>{escape(o['name'])}</option>" for o in orgs)
    roleopts=''.join(f"<option value='{r}'>{r.replace('_',' ').title()}</option>" for r in roles)
    create=f"<div class='panel'><h2>Create user</h2><form class='actions' method='post' action='/admin/users'><input name='username' placeholder='Username' required><input name='display_name' placeholder='Display name'><input name='password' type='password' placeholder='Temporary password' required><select name='role'>{roleopts}</select><select name='organization_id'>{orgopts}</select><button class='btn-primary'>Create user</button></form></div>"
    row_parts=[]
    for u in users:
        reset_mfa = '' if not u['mfa_enabled'] or u['id']==principal.id else f"<form method='post' action='/admin/users/{u['id']}/reset-mfa'><button class='btn-warning'>Reset MFA</button></form>"
        actions=f"<form class='actions' method='post' action='/admin/users/{u['id']}/reset-password'><input name='password' type='password' placeholder='New temporary password' required><button>Reset password</button></form>{reset_mfa}"
        if u['id']!=principal.id:
            actions += f"<form method='post' action='/admin/users/{u['id']}/toggle'><button>{'Disable' if u['active'] else 'Enable'}</button></form>"
            if not u['active']:
                actions += f"<form method='post' action='/admin/users/{u['id']}/delete'><button class='btn-danger'>Delete</button></form>"
        row_parts.append(f"<tr><td>{escape(u['username'])}</td><td>{escape(u['display_name'] or '')}</td><td>{escape(u['role'].replace('_',' ').title())}</td><td>{escape(u['organization_name'] or 'Global')}</td><td>{'Enabled' if u['active'] else 'Disabled'}</td><td>{display_time(u['last_login'])}</td><td>{'Enabled' if u['mfa_enabled'] else 'Not configured'}</td><td><div class='action-stack'>{actions}</div></td></tr>")
    rows=''.join(row_parts)
    return page('User Management',create+f"<div class='card'><table><tr><th>Username</th><th>Name</th><th>Role</th><th>Organization</th><th>Status</th><th>Last login</th><th>MFA</th><th>Action</th></tr>{rows}</table></div><p class='muted'>Users can enroll a TOTP authenticator from Security / MFA. Administrators can reset MFA if a user loses access to the authenticator and recovery codes.</p>",principal)


@app.get('/account', response_class=HTMLResponse)
def account_page(principal:Principal=Depends(admin_auth)):
    with db() as conn:
        user=conn.execute("SELECT u.*,o.name organization_name FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.id=?",(principal.id,)).fetchone()
    if not user: raise HTTPException(status_code=404,detail='User account not found')
    body=f"""<div class='panel'><div class='grid'>
      <div><div class='muted'>Username</div><b>{escape(user['username'])}</b></div>
      <div><div class='muted'>Display name</div><b>{escape(user['display_name'] or user['username'])}</b></div>
      <div><div class='muted'>Role</div><b>{escape(user['role'].replace('_',' ').title())}</b></div>
      <div><div class='muted'>Organization</div><b>{escape(user['organization_name'] or 'Global')}</b></div>
      <div><div class='muted'>Last login</div><b>{escape(user['last_login'] or '')}</b></div>
      <div><div class='muted'>MFA</div><b>{'Configured' if user['mfa_enabled'] else 'Not configured'}</b></div>
    </div><p style='margin-top:18px' class='actions'><a href='/account/password'><button class='btn-primary'>Change Password</button></a><a href='/account/security'><button>Security / MFA</button></a></p></div>"""
    return page('My Account',body,principal)


@app.get('/account/password', response_class=HTMLResponse)
def password_page(principal:Principal=Depends(admin_auth)):
    body="<div class='panel'><form method='post' action='/account/password'><div class='field'><label>Current password</label><input type='password' name='current_password' required></div><div class='field'><label>New password</label><input type='password' name='new_password' minlength='10' required></div><div class='field'><label>Confirm new password</label><input type='password' name='confirm_password' minlength='10' required></div><button class='btn-primary'>Change password</button></form><p class='muted'>Changing your password signs out your other AppControl Manager web sessions.</p></div>"
    return page('Change Password',body,principal)


@app.post('/account/password', response_class=HTMLResponse)
def change_password(request:Request, current_password:str=Form(...), new_password:str=Form(...), confirm_password:str=Form(...), principal:Principal=Depends(admin_auth)):
    if len(new_password)<10 or new_password!=confirm_password: raise HTTPException(status_code=400,detail='New passwords must match and be at least 10 characters.')
    current_token=request.cookies.get(SESSION_COOKIE)
    with db() as conn:
        row=conn.execute('SELECT password_hash FROM users WHERE id=?',(principal.id,)).fetchone()
        if not row or not password_verify(current_password,row['password_hash']): raise HTTPException(status_code=400,detail='Current password is incorrect.')
        conn.execute('UPDATE users SET password_hash=?,force_password_change=0 WHERE id=?',(password_hash(new_password),principal.id))
        if current_token:
            conn.execute('DELETE FROM web_sessions WHERE user_id=? AND token_hash<>?',(principal.id,_session_hash(current_token)))
        else:
            conn.execute('DELETE FROM web_sessions WHERE user_id=?',(principal.id,))
        audit(conn,principal.username,'password_changed',organization_id=principal.organization_id,object_type='user',object_id=principal.id)
    return page('Password changed',"<div class='panel'><p>Your password has been changed. Other web sessions for this account were signed out.</p><a href='/'><button class='btn-primary'>Return to Dashboard</button></a></div>",principal)


@app.post('/admin/requests/{request_id}/approve')
def approve(request_id:int, scope_type:str=Form('device'), principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        r=conn.execute('SELECT r.*,d.organization_id,d.group_id FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE r.id=?',(request_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Request not found')
        require_org_access(principal,r['organization_id'])
        if r['status']!='pending': return RedirectResponse('/',status_code=303)
        if active_device_command(conn,r['device_id']): return RedirectResponse('/?busy=1',status_code=303)
        items=conn.execute('SELECT * FROM approval_request_items WHERE request_id=? ORDER BY id',(request_id,)).fetchall()
        if not items: items=[dict(original_path=r['file_path'],policy_source_path=r['policy_source_path'],sha256=r['sha256'],publisher=r['publisher'],product_name=r['product_name'],file_version=r['file_version'])]
        uncovered=[]
        for item in items:
            probe=ApprovalIn(file_path=item['original_path'],policy_source_path=item['policy_source_path'],sha256=item['sha256'],publisher=item['publisher'],product_name=item['product_name'],file_version=item['file_version'])
            if find_existing_block(conn,r['device_id'],probe):
                conn.execute("UPDATE approval_requests SET status='denied',decided_at=?,decided_by=?,decision_note=? WHERE id=?",(utcnow(),principal.username,'Explicit AppControl Manager block policy exists.',request_id)); return RedirectResponse('/',status_code=303)
            if not find_existing_approved(conn,r['device_id'],probe): uncovered.append(item)
        if not uncovered:
            conn.execute("UPDATE approval_requests SET status='approved_existing',decided_at=?,decided_by=?,decision_note=? WHERE id=?",(utcnow(),principal.username,'Already covered by an existing policy.',request_id)); return RedirectResponse('/',status_code=303)
        scoped_policy_id=create_scoped_policy(conn,r,principal,scope_type,None,'allow')
        if len(items)>1 or r['request_kind']=='session':
            payload=json.dumps({'request_id':request_id,'components':[{'file_path':i['original_path'],'policy_source_path':i['policy_source_path']} for i in uncovered],'scoped_policy_id':scoped_policy_id}); command_type='approve_session'
        else:
            i=uncovered[0]; payload=json.dumps({'request_id':request_id,'file_path':i['original_path'],'policy_source_path':i['policy_source_path'],'scoped_policy_id':scoped_policy_id}); command_type='approve_file'
        conn.execute('INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)',(r['device_id'],command_type,payload,'pending',utcnow()))
        conn.execute("UPDATE approval_requests SET status='approving',decided_at=?,decided_by=?,decision_note=? WHERE id=?",(utcnow(),principal.username,f'Approved with {scope_type} scope policy #{scoped_policy_id}.',request_id))
        audit(conn,principal.username,'request_approved',organization_id=r['organization_id'],device_id=r['device_id'],object_type='approval_request',object_id=request_id,detail=f'scope={scope_type}; policy={scoped_policy_id}')
    return RedirectResponse('/',status_code=303)


@app.get('/requests/{request_id}/deny', response_class=HTMLResponse)
def deny_request_page(request_id:int, principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        r=conn.execute('SELECT r.*,d.hostname,d.organization_id FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE r.id=?',(request_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Request not found')
        require_org_access(principal,r['organization_id'])
    if r['status']!='pending':
        body=f"<div class='notice-info'>Request #{request_id} is already <b>{escape(r['status'])}</b>.</div><a class='button' href='/requests/{request_id}'>Back to request</a>"
        return page(f'Deny Request #{request_id}',body,principal,subtitle='This request no longer requires a denial decision.')
    app_name=r['product_name'] or filename(r['file_path'])
    body=f"""<div class='panel'>
      <h2 style='margin-top:0'>Deny application request</h2>
      <div class='details-grid'>
        <div class='detail-item'><span class='muted'>Application</span><b>{escape(app_name)}</b><div class='file-sub'>{escape(r['file_path'])}</div></div>
        <div class='detail-item'><span class='muted'>Device</span><b>{escape(r['hostname'])}</b></div>
        <div class='detail-item'><span class='muted'>Requested by</span><b>{escape(r['requested_by'] or 'Unknown')}</b></div>
        <div class='detail-item'><span class='muted'>User request reason</span>{escape(r['reason'] or 'No reason supplied.')}</div>
      </div>
      <form method='post' action='/admin/requests/{request_id}/deny' style='margin-top:20px'>
        <div class='field'>
          <label>Message to end user (optional)</label>
          <textarea name='denial_message' rows='6' maxlength='1000' style='width:100%;min-width:0' placeholder='Example: This application has been identified as malicious and is not permitted on company computers.'></textarea>
          <div class='muted'>This message is saved with the request and shown to the requesting user. If left blank, AppControl Manager will use “Denied by administrator.”</div>
        </div>
        <div class='actions'><button class='btn-warning'>Deny request</button><a class='button' href='/requests/{request_id}'>Cancel</a></div>
      </form>
    </div>"""
    return page(f'Deny Request #{request_id}',body,principal,subtitle='Optionally explain why the application request is being denied.')


@app.post('/admin/requests/{request_id}/deny')
def deny(request_id:int, denial_message:str=Form(''), principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    message=(denial_message or '').strip()
    if len(message)>1000:
        raise HTTPException(status_code=400,detail='Denial message must be 1000 characters or fewer.')
    if not message:
        message='Denied by administrator.'
    with db() as conn:
        r=conn.execute('SELECT r.*,d.organization_id FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE r.id=?',(request_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Request not found')
        require_org_access(principal,r['organization_id'])
        cur=conn.execute("UPDATE approval_requests SET status='denied',decided_at=?,decided_by=?,decision_note=? WHERE id=? AND status='pending'",(utcnow(),principal.username,message,request_id))
        if cur.rowcount:
            audit(conn,principal.username,'request_denied',organization_id=r['organization_id'],device_id=r['device_id'],object_type='approval_request',object_id=request_id,detail=f'denial_message={message}')
    return RedirectResponse(f'/requests/{request_id}',status_code=303)


@app.post('/admin/requests/{request_id}/block')
def block_request(request_id:int, scope_type:str=Form('device'), principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        r=conn.execute('SELECT r.*,d.organization_id,d.group_id FROM approval_requests r JOIN devices d ON d.id=r.device_id WHERE r.id=?',(request_id,)).fetchone()
        if not r: raise HTTPException(status_code=404,detail='Request not found')
        require_org_access(principal,r['organization_id'])
        if r['status']!='pending': return RedirectResponse('/',status_code=303)
        scoped_id=create_scoped_policy(conn,r,principal,scope_type,None,'block',request_id)
        policy=conn.execute('SELECT * FROM scoped_policies WHERE id=?',(scoped_id,)).fetchone()
        ensure_scoped_block_on_device(conn,r['device_id'],r,policy,principal.username)
        queued,unknown=rollout_scoped_block(conn,policy,principal.username)
        conn.execute("UPDATE approval_requests SET status='blocked',decided_at=?,decided_by=?,decision_note=? WHERE id=?",
                     (utcnow(),principal.username,f'Blocked by {scope_type} policy #{scoped_id}.',request_id))
        audit(conn,principal.username,'request_blocked',organization_id=r['organization_id'],device_id=r['device_id'],object_type='approval_request',object_id=request_id,detail=f'scope={scope_type}; policy={scoped_id}; rollout={queued}; no_known_source={unknown}')
    return RedirectResponse('/policies',status_code=303)


def _policy_source_for_component(conn: sqlite3.Connection, component: sqlite3.Row) -> Optional[str]:
    if component['request_id']:
        item = conn.execute(
            """SELECT policy_source_path FROM approval_request_items
               WHERE request_id=? AND lower(original_path)=lower(?) ORDER BY id DESC LIMIT 1""",
            (component['request_id'], component['file_path']),
        ).fetchone()
        if item and item['policy_source_path']:
            return item['policy_source_path']
    return None


def _queue_block(conn: sqlite3.Connection, *, device_id: str, file_path: str, policy_source_path: Optional[str], sha256: Optional[str],
                 publisher: Optional[str], product_name: Optional[str], file_version: Optional[str], admin_user: str,
                 source_component_id: Optional[int] = None, source_request_id: Optional[int] = None,
                 policy_definition_id: Optional[int] = None, block_note: Optional[str] = None) -> int:
    active = conn.execute(
        """SELECT id FROM blocked_applications WHERE device_id=? AND
           ((? IS NOT NULL AND sha256=?) OR lower(file_path)=lower(?)) AND status IN ('blocking','blocked','unblocking')
           ORDER BY id DESC LIMIT 1""",
        (device_id, sha256, sha256, file_path),
    ).fetchone()
    if active:
        return active['id']

    # Retry the newest failed block in-place instead of creating another duplicate failed row.
    failed = conn.execute(
        """SELECT id FROM blocked_applications WHERE device_id=? AND
           ((? IS NOT NULL AND sha256=?) OR lower(file_path)=lower(?)) AND status='failed'
           ORDER BY id DESC LIMIT 1""",
        (device_id, sha256, sha256, file_path),
    ).fetchone()
    if failed:
        block_id = failed['id']
        conn.execute(
            """UPDATE blocked_applications SET source_component_id=COALESCE(?,source_component_id),
               source_request_id=COALESCE(?,source_request_id),policy_definition_id=COALESCE(?,policy_definition_id),policy_source_path=?,sha256=?,publisher=?,product_name=?,file_version=?,
               status='blocking',created_at=?,blocked_at=NULL,blocked_by=?,note=? WHERE id=?""",
            (source_component_id, source_request_id, policy_definition_id, policy_source_path, sha256, publisher, product_name, file_version,
             utcnow(), admin_user, block_note or 'Retrying explicit block after previous failure.', block_id),
        )
    else:
        cur = conn.execute(
            """INSERT INTO blocked_applications
               (device_id,source_component_id,source_request_id,policy_definition_id,file_path,policy_source_path,sha256,publisher,product_name,file_version,status,created_at,blocked_by,note)
               VALUES(?,?,?,?,?,?,?,?,?,?,'blocking',?,?,?)""",
            (device_id, source_component_id, source_request_id, policy_definition_id, file_path, policy_source_path, sha256, publisher, product_name,
             file_version, utcnow(), admin_user, block_note or 'Block requested by administrator.'),
        )
        block_id = cur.lastrowid

    pending = conn.execute(
        "SELECT id FROM commands WHERE device_id=? AND command_type='block_file' AND status='pending' AND payload LIKE ? LIMIT 1",
        (device_id, f'%\"block_id\": {block_id}%'),
    ).fetchone()
    if not pending:
        conn.execute(
            "INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",
            (device_id, 'block_file', json.dumps({
                'block_id': block_id, 'file_path': file_path, 'policy_source_path': policy_source_path, 'requested_by': admin_user, 'scoped_policy_id': policy_definition_id
            }), 'pending', utcnow()),
        )
    return block_id


def scoped_policy_devices(conn: sqlite3.Connection, policy: sqlite3.Row) -> list[sqlite3.Row]:
    st, sid = policy['scope_type'], policy['scope_id']
    if st == 'global':
        return conn.execute("SELECT * FROM devices ORDER BY hostname").fetchall()
    if st == 'organization':
        return conn.execute("SELECT * FROM devices WHERE organization_id=? ORDER BY hostname", (sid,)).fetchall()
    if st == 'group':
        return conn.execute("SELECT * FROM devices WHERE group_id=? ORDER BY hostname", (sid,)).fetchall()
    if st == 'device':
        row = conn.execute("SELECT * FROM devices WHERE id=?", (sid,)).fetchone()
        return [row] if row else []
    return []


def _known_source_for_scoped_policy(conn: sqlite3.Connection, device_id: str, policy: sqlite3.Row):
    for row in conn.execute("SELECT * FROM approved_components WHERE device_id=? ORDER BY id DESC LIMIT 500", (device_id,)).fetchall():
        if policy_identity_matches(policy, row):
            return {
                'file_path': row['file_path'], 'policy_source_path': _policy_source_for_component(conn, row),
                'sha256': row['sha256'], 'publisher': row['publisher'], 'product_name': row['product_name'],
                'file_version': row['file_version'], 'source_component_id': row['id'], 'source_request_id': row['request_id'],
            }
    for row in conn.execute("SELECT * FROM events WHERE device_id=? AND file_path IS NOT NULL AND file_path<>'' ORDER BY id DESC LIMIT 1000", (device_id,)).fetchall():
        if policy_identity_matches(policy, row):
            return {
                'file_path': row['file_path'], 'policy_source_path': None, 'sha256': row['sha256'],
                'publisher': row['publisher'], 'product_name': row['product_name'], 'file_version': row['file_version'],
                'source_component_id': None, 'source_request_id': None,
            }
    return None


def ensure_scoped_block_on_device(conn: sqlite3.Connection, device_id: str, req, policy: sqlite3.Row, actor: str = 'policy-engine') -> Optional[int]:
    if not policy or not policy['active'] or policy['action'] != 'block' or not device_matches_policy_scope(conn, device_id, policy):
        return None
    file_path = objv(req, 'file_path') or objv(req, 'original_path')
    if not file_path:
        return None
    return _queue_block(
        conn, device_id=device_id, file_path=file_path, policy_source_path=objv(req, 'policy_source_path'),
        sha256=objv(req, 'sha256'), publisher=objv(req, 'publisher'), product_name=objv(req, 'product_name'),
        file_version=objv(req, 'file_version'), admin_user=actor, policy_definition_id=policy['id'],
    )


def rollout_scoped_block(conn: sqlite3.Connection, policy: sqlite3.Row, actor: str) -> tuple[int,int]:
    queued = 0; unknown = 0
    for device in scoped_policy_devices(conn, policy):
        source = _known_source_for_scoped_policy(conn, device['id'], policy)
        if not source:
            unknown += 1
            continue
        before = conn.execute("SELECT COUNT(*) n FROM blocked_applications WHERE device_id=? AND policy_definition_id=? AND status IN ('blocking','blocked','unblocking')", (device['id'], policy['id'])).fetchone()['n']
        _queue_block(
            conn, device_id=device['id'], file_path=source['file_path'], policy_source_path=source['policy_source_path'],
            sha256=source['sha256'], publisher=source['publisher'], product_name=source['product_name'], file_version=source['file_version'],
            admin_user=actor, source_component_id=source['source_component_id'], source_request_id=source['source_request_id'],
            policy_definition_id=policy['id'],
        )
        after = conn.execute("SELECT COUNT(*) n FROM blocked_applications WHERE device_id=? AND policy_definition_id=? AND status IN ('blocking','blocked','unblocking')", (device['id'], policy['id'])).fetchone()['n']
        if after > before:
            queued += 1
    return queued, unknown


@app.post("/admin/approved/{component_id}/revoke")
def revoke_approved(component_id: int, principal: Principal = Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        row=conn.execute("SELECT a.*,d.organization_id FROM approved_components a JOIN devices d ON d.id=a.device_id WHERE a.id=?",(component_id,)).fetchone()
        if not row: raise HTTPException(status_code=404,detail='Approved component not found')
        require_org_access(principal,row['organization_id'])
        if row['policy_definition_id']:
            pdef=conn.execute('SELECT * FROM scoped_policies WHERE id=?',(row['policy_definition_id'],)).fetchone()
            if pdef and pdef['active']:
                if pdef['scope_type']=='global' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Global administrator required')
                conn.execute('UPDATE scoped_policies SET active=0,disabled_at=?,disabled_by=? WHERE id=?',(utcnow(),principal.username,pdef['id']))
                linked=conn.execute("SELECT DISTINCT device_id,policy_id FROM approved_components WHERE policy_definition_id=? AND status='approved'",(pdef['id'],)).fetchall()
                for link in linked:
                    if re.fullmatch(r'[0-9A-Fa-f-]{36}',link['policy_id'] or ''):
                        conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",(link['device_id'],'revoke_approval',json.dumps({'policy_id':link['policy_id'],'requested_by':principal.username,'scoped_policy_id':pdef['id']}),'pending',utcnow()))
                        conn.execute("UPDATE approved_components SET status='revoking' WHERE device_id=? AND policy_id=? AND status='approved'",(link['device_id'],link['policy_id']))
                        conn.execute("UPDATE approved_applications SET status='revoking' WHERE device_id=? AND policy_id=? AND status='approved'",(link['device_id'],link['policy_id']))
                audit(conn,principal.username,'scoped_policy_disabled',organization_id=pdef['organization_id'],object_type='scoped_policy',object_id=pdef['id'],detail=f'revokes queued={len(linked)}')
                return RedirectResponse('/approved',status_code=303)
        if active_device_command(conn,row['device_id']): return RedirectResponse('/approved?busy=1',status_code=303)
        policy_id=row['policy_id'] or ''
        if not re.fullmatch(r'[0-9A-Fa-f-]{36}',policy_id): raise HTTPException(status_code=400,detail='Approval does not have a removable policy GUID.')
        conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",(row['device_id'],'revoke_approval',json.dumps({'policy_id':policy_id,'requested_by':principal.username}),'pending',utcnow()))
        conn.execute("UPDATE approved_components SET status='revoking' WHERE device_id=? AND policy_id=? AND status IN ('approved','blocked')",(row['device_id'],policy_id))
        conn.execute("UPDATE approved_applications SET status='revoking' WHERE device_id=? AND policy_id=? AND status='approved'",(row['device_id'],policy_id))
        audit(conn,principal.username,'approval_revoke_queued',organization_id=row['organization_id'],device_id=row['device_id'],object_type='approved_component',object_id=component_id)
    return RedirectResponse('/approved',status_code=303)


@app.post("/admin/approved/{component_id}/block")
def block_approved(component_id:int, scope_type:str=Form('device'), principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        row=conn.execute("SELECT a.*,d.organization_id,d.group_id FROM approved_components a JOIN devices d ON d.id=a.device_id WHERE a.id=?",(component_id,)).fetchone()
        if not row: raise HTTPException(status_code=404,detail='Approved component not found')
        require_org_access(principal,row['organization_id'])
        scoped_id=create_scoped_policy(conn,row,principal,scope_type,None,'block',row['request_id'])
        policy=conn.execute('SELECT * FROM scoped_policies WHERE id=?',(scoped_id,)).fetchone()
        queued,unknown=rollout_scoped_block(conn,policy,principal.username)
        audit(conn,principal.username,'scoped_block_rollout',organization_id=policy['organization_id'],device_id=row['device_id'],object_type='scoped_policy',object_id=scoped_id,detail=f'queued={queued}; no_known_source={unknown}')
    return RedirectResponse('/policies',status_code=303)


@app.post("/admin/observed/{event_id}/block")
def block_observed(event_id:int, scope_type:str=Form('device'), principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        row=conn.execute("SELECT e.*,d.organization_id,d.group_id FROM events e JOIN devices d ON d.id=e.device_id WHERE e.id=?",(event_id,)).fetchone()
        if not row: raise HTTPException(status_code=404,detail='Observed application not found')
        require_org_access(principal,row['organization_id'])
        scoped_id=create_scoped_policy(conn,row,principal,scope_type,None,'block',None)
        policy=conn.execute('SELECT * FROM scoped_policies WHERE id=?',(scoped_id,)).fetchone()
        queued,unknown=rollout_scoped_block(conn,policy,principal.username)
        audit(conn,principal.username,'scoped_block_rollout',organization_id=policy['organization_id'],device_id=row['device_id'],object_type='scoped_policy',object_id=scoped_id,detail=f'queued={queued}; no_known_source={unknown}')
    return RedirectResponse('/policies',status_code=303)


@app.post("/admin/blocked/{block_id}/retry")
def retry_block(block_id:int, principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        row=conn.execute("SELECT b.*,d.organization_id FROM blocked_applications b JOIN devices d ON d.id=b.device_id WHERE b.id=?",(block_id,)).fetchone()
        if not row: raise HTTPException(status_code=404,detail='Blocked application not found')
        require_org_access(principal,row['organization_id'])
        if row['status']!='failed': return RedirectResponse('/blocked',status_code=303)
        if active_device_command(conn,row['device_id']): return RedirectResponse('/blocked?busy=1',status_code=303)
        _queue_block(conn,device_id=row['device_id'],file_path=row['file_path'],policy_source_path=row['policy_source_path'],sha256=row['sha256'],publisher=row['publisher'],product_name=row['product_name'],file_version=row['file_version'],admin_user=principal.username,source_component_id=row['source_component_id'],source_request_id=row['source_request_id'])
        audit(conn,principal.username,'explicit_block_retry_queued',organization_id=row['organization_id'],device_id=row['device_id'],object_type='blocked_application',object_id=block_id,detail=row['file_path'])
    return RedirectResponse(f'/blocked/{block_id}',status_code=303)


@app.post("/admin/blocked/{block_id}/unblock")
def unblock(block_id:int, principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        row=conn.execute("SELECT b.*,d.organization_id FROM blocked_applications b JOIN devices d ON d.id=b.device_id WHERE b.id=?",(block_id,)).fetchone()
        if not row: raise HTTPException(status_code=404,detail='Blocked application not found')
        require_org_access(principal,row['organization_id'])
        if row['status']!='blocked' or not row['policy_id']: return RedirectResponse('/blocked',status_code=303)
        if active_device_command(conn,row['device_id']): return RedirectResponse('/blocked?busy=1',status_code=303)
        conn.execute('INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)',(row['device_id'],'unblock_file',json.dumps({'block_id':block_id,'policy_id':row['policy_id'],'requested_by':principal.username}),'pending',utcnow()))
        conn.execute("UPDATE blocked_applications SET status='unblocking' WHERE id=?",(block_id,))
        audit(conn,principal.username,'explicit_unblock_queued',organization_id=row['organization_id'],device_id=row['device_id'],object_type='blocked_application',object_id=block_id,detail=row['file_path'])
    return RedirectResponse(f'/blocked/{block_id}',status_code=303)



@app.post('/admin/devices/bulk')
async def bulk_device_action(request:Request, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    form=await request.form(); device_ids=[str(v) for v in form.getlist('device_ids') if str(v).strip()]
    action=str(form.get('bulk_action') or '').strip(); group_value=str(form.get('bulk_group_id') or '').strip()
    if not device_ids: return RedirectResponse('/devices?bulk_result='+quote('No devices were selected.'),status_code=303)
    if action not in {'learning','enforcement','group'}: return RedirectResponse('/devices?bulk_result='+quote('Choose a bulk action first.'),status_code=303)
    changed=0; skipped=0
    with db() as conn:
        target_group=None
        if action=='group' and group_value:
            target_group=conn.execute('SELECT * FROM device_groups WHERE id=?',(int(group_value),)).fetchone()
            if not target_group: raise HTTPException(status_code=400,detail='Invalid device group')
            if not principal.can_manage_global and target_group['organization_id']!=principal.organization_id: raise HTTPException(status_code=403,detail='Device group is outside your organization.')
        for device_id in device_ids[:250]:
            d=conn.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
            if not d or not principal_can_see_org(principal,d['organization_id']): skipped+=1; continue
            if action=='group':
                if target_group and target_group['organization_id']!=d['organization_id']:
                    skipped+=1; continue
                gid=target_group['id'] if target_group else None
                conn.execute('UPDATE devices SET group_id=? WHERE id=?',(gid,device_id)); audit(conn,principal.username,'device_group_changed',organization_id=d['organization_id'],device_id=device_id,object_type='device',object_id=device_id,detail=f'bulk group_id={gid}'); changed+=1
                continue
            if active_device_command(conn,device_id): skipped+=1; continue
            cmd='enable_enforcement' if action=='enforcement' else 'return_to_learning'
            conn.execute('INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)',(device_id,cmd,json.dumps({'requested_by':principal.username,'bulk':True}),'pending',utcnow())); audit(conn,principal.username,'bulk_device_mode_requested',organization_id=d['organization_id'],device_id=device_id,object_type='device',object_id=device_id,detail=cmd); changed+=1
    label={'learning':'Learning mode','enforcement':'Enforcement mode','group':'device group'}[action]
    message=f'Bulk action queued/applied: {label} for {changed} device(s).'
    if skipped: message += f' {skipped} device(s) were skipped because of scope, group mismatch, missing records, or an active endpoint command.'
    return RedirectResponse('/devices?bulk_result='+quote(message),status_code=303)

@app.post("/admin/devices/{device_id}/learning")
def return_device_to_learning(device_id:str, principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        d=conn.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not d: raise HTTPException(status_code=404,detail='Device not found')
        require_org_access(principal,d['organization_id'])
        if active_device_command(conn,device_id): return RedirectResponse('/?busy=1',status_code=303)
        conn.execute('INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)',(device_id,'return_to_learning',json.dumps({'requested_by':principal.username}),'pending',utcnow()))
    return RedirectResponse('/',status_code=303)


@app.post("/admin/devices/{device_id}/enforcement")
def enable_device_enforcement(device_id:str, principal:Principal=Depends(admin_auth)):
    require_approver(principal)
    with db() as conn:
        d=conn.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not d: raise HTTPException(status_code=404,detail='Device not found')
        require_org_access(principal,d['organization_id'])
        if active_device_command(conn,device_id): return RedirectResponse('/?busy=1',status_code=303)
        conn.execute('INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)',(device_id,'enable_enforcement',json.dumps({'requested_by':principal.username}),'pending',utcnow()))
    return RedirectResponse('/',status_code=303)


@app.post('/admin/devices/{device_id}/group')
def assign_device_group(device_id:str, group_id:str=Form(''), principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        d=conn.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
        if not d: raise HTTPException(status_code=404,detail='Device not found')
        require_org_access(principal,d['organization_id'])
        gid=int(group_id) if group_id else None
        if gid:
            g=conn.execute('SELECT * FROM device_groups WHERE id=?',(gid,)).fetchone()
            if not g or g['organization_id']!=d['organization_id']: raise HTTPException(status_code=400,detail='Invalid device group')
        conn.execute('UPDATE devices SET group_id=? WHERE id=?',(gid,device_id))
        audit(conn,principal.username,'device_group_changed',organization_id=d['organization_id'],device_id=device_id,object_type='device',object_id=device_id,detail=f'group_id={gid}')
    return RedirectResponse(f'/devices/{device_id}',status_code=303)


@app.post('/admin/organizations')
def create_organization(name:str=Form(...), principal:Principal=Depends(admin_auth)):
    if not principal.can_manage_global: raise HTTPException(status_code=403,detail='Global administrator required')
    with db() as conn:
        base=slugify(name); slug=base; n=2
        while conn.execute('SELECT id FROM organizations WHERE slug=?',(slug,)).fetchone(): slug=f'{base}-{n}'; n+=1
        cur=conn.execute("INSERT INTO organizations(name,slug,status,created_at) VALUES(?,?,'active',?)",(name.strip(),slug,utcnow()))
        audit(conn,principal.username,'organization_created',organization_id=cur.lastrowid,object_type='organization',object_id=cur.lastrowid,detail=name)
    return RedirectResponse('/organizations',status_code=303)


@app.post('/admin/organizations/{org_id}/keys', response_class=HTMLResponse)
def create_enrollment_key(org_id:int, request:Request, name:str=Form(...), principal:Principal=Depends(admin_auth)):
    require_org_admin(principal); require_org_access(principal,org_id)
    token=secrets.token_urlsafe(32)
    with db() as conn:
        org=conn.execute('SELECT * FROM organizations WHERE id=?',(org_id,)).fetchone()
        if not org: raise HTTPException(status_code=404,detail='Organization not found')
        conn.execute("INSERT INTO enrollment_keys(organization_id,name,token_hash,token_prefix,token_value,active,created_at,created_by) VALUES(?,?,?,?,?,1,?,?)",(org_id,name,hash_key(token),token[:8],token,utcnow(),principal.username))
        audit(conn,principal.username,'enrollment_key_created',organization_id=org_id,object_type='organization',object_id=org_id,detail=name)
    base=str(request.base_url).rstrip('/'); silent=f'AppControlManager-Installer.exe /server {base} /key {token} /silent'
    body=f"<div class='notice-info'><b>This enrollment token is reusable.</b> It remains active until you disable it and can be embedded in VSA X or other onboarding workflows.</div><div class='panel'><h3>Enrollment token</h3><div class='copy-wrap'><code id='new-enrollment-token' data-copy='{escape(token)}' style='font-size:14px'>{escape(token)}</code><button type='button' class='copy-btn' onclick=\"acmCopy('new-enrollment-token',this)\">Copy</button></div><h3>Single-file installation</h3><p><a href='/downloads/installer/latest'>Download latest stable Windows installer</a></p><p class='muted'>Interactive install: run the EXE and enter the server URL and this enrollment token. Silent deployment:</p><div class='copy-wrap'><code id='new-enrollment-command' data-copy='{escape(silent)}'>{escape(silent)}</code><button type='button' class='copy-btn' onclick=\"acmCopy('new-enrollment-command',this)\">Copy</button></div></div><p><a href='/organizations'>Return to Organizations</a></p>"
    return page(f'Enrollment Token - {org["name"]}',body,principal)


@app.post('/admin/organizations/{org_id}/groups')
def create_group(org_id:int, name:str=Form(...), description:str=Form(''), principal:Principal=Depends(admin_auth)):
    require_org_admin(principal); require_org_access(principal,org_id)
    with db() as conn:
        conn.execute('INSERT INTO device_groups(organization_id,name,description,created_at) VALUES(?,?,?,?)',(org_id,name.strip(),description.strip(),utcnow()))
        audit(conn,principal.username,'device_group_created',organization_id=org_id,object_type='device_group',detail=name)
    return RedirectResponse('/organizations',status_code=303)


@app.post('/admin/users')
def create_user(username:str=Form(...), display_name:str=Form(''), password:str=Form(...), role:str=Form(...), organization_id:str=Form(''), principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    if len(password)<10: raise HTTPException(status_code=400,detail='Temporary password must be at least 10 characters.')
    allowed={'org_admin','approver','read_only'} | ({'global_admin'} if principal.can_manage_global else set())
    if role not in allowed: raise HTTPException(status_code=400,detail='Invalid role')
    org_id=int(organization_id) if organization_id else None
    if role!='global_admin':
        if org_id is None:
            if principal.organization_id is None:
                raise HTTPException(status_code=400,detail='Select an organization for non-global users.')
            org_id=principal.organization_id
        require_org_access(principal,org_id)
    elif not principal.can_manage_global: raise HTTPException(status_code=403,detail='Cannot create global administrator')
    with db() as conn:
        conn.execute("INSERT INTO users(username,password_hash,display_name,role,organization_id,active,force_password_change,created_at,created_by) VALUES(?,?,?,?,?,1,1,?,?)",(username.strip(),password_hash(password),display_name.strip(),role,org_id,utcnow(),principal.username))
        audit(conn,principal.username,'user_created',organization_id=org_id,object_type='user',detail=f'{username} role={role}')
    return RedirectResponse('/users',status_code=303)


@app.post('/admin/users/{user_id}/reset-password')
def reset_user_password(user_id:int, password:str=Form(...), principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    if len(password)<10: raise HTTPException(status_code=400,detail='Password must be at least 10 characters.')
    with db() as conn:
        u=conn.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        if not u: raise HTTPException(status_code=404,detail='User not found')
        if u['role']=='global_admin' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Cannot reset global administrator')
        if u['organization_id'] is not None: require_org_access(principal,u['organization_id'])
        conn.execute('UPDATE users SET password_hash=?,force_password_change=1 WHERE id=?',(password_hash(password),user_id))
        conn.execute('DELETE FROM web_sessions WHERE user_id=?',(user_id,))
        audit(conn,principal.username,'user_password_reset',organization_id=u['organization_id'],object_type='user',object_id=user_id,detail=u['username'])
    return RedirectResponse('/users',status_code=303)


@app.post('/admin/users/{user_id}/toggle')
def toggle_user(user_id:int, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    if user_id==principal.id: raise HTTPException(status_code=400,detail='You cannot disable your own account.')
    with db() as conn:
        u=conn.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        if not u: raise HTTPException(status_code=404,detail='User not found')
        if u['role']=='global_admin' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Cannot change global administrator')
        if u['organization_id'] is not None: require_org_access(principal,u['organization_id'])
        new=0 if u['active'] else 1
        conn.execute('UPDATE users SET active=? WHERE id=?',(new,user_id))
        if not new: conn.execute('DELETE FROM web_sessions WHERE user_id=?',(user_id,))
        audit(conn,principal.username,'user_enabled' if new else 'user_disabled',organization_id=u['organization_id'],object_type='user',object_id=user_id,detail=u['username'])
    return RedirectResponse('/users',status_code=303)



@app.post('/admin/users/{user_id}/reset-mfa')
def reset_user_mfa(user_id:int, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    if user_id==principal.id: raise HTTPException(status_code=400,detail='Use Security / MFA to manage your own MFA.')
    with db() as conn:
        u=conn.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        if not u: raise HTTPException(status_code=404,detail='User not found')
        if u['role']=='global_admin' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Cannot reset global administrator MFA')
        if u['organization_id'] is not None: require_org_access(principal,u['organization_id'])
        conn.execute('UPDATE users SET mfa_enabled=0,mfa_secret=NULL,mfa_recovery_codes=NULL WHERE id=?',(user_id,))
        conn.execute('DELETE FROM web_sessions WHERE user_id=?',(user_id,))
        audit(conn,principal.username,'user_mfa_reset',organization_id=u['organization_id'],object_type='user',object_id=user_id,detail=u['username'])
    return RedirectResponse('/users',status_code=303)


@app.post('/admin/enrollment-keys/{key_id}/disable')
def disable_enrollment_key(key_id:int, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        k=conn.execute('SELECT * FROM enrollment_keys WHERE id=?',(key_id,)).fetchone()
        if not k: raise HTTPException(status_code=404,detail='Enrollment key not found')
        require_org_access(principal,k['organization_id'])
        conn.execute('UPDATE enrollment_keys SET active=0 WHERE id=?',(key_id,))
        audit(conn,principal.username,'enrollment_key_disabled',organization_id=k['organization_id'],object_type='enrollment_key',object_id=key_id,detail=k['name'])
    return RedirectResponse('/organizations',status_code=303)


@app.post('/admin/users/{user_id}/delete')
def delete_user(user_id:int, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    if user_id==principal.id: raise HTTPException(status_code=400,detail='You cannot delete your own account.')
    with db() as conn:
        u=conn.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        if not u: raise HTTPException(status_code=404,detail='User not found')
        if u['active']: raise HTTPException(status_code=400,detail='Disable the user before deleting the account.')
        if u['role']=='global_admin' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Cannot delete global administrator')
        if u['organization_id'] is not None: require_org_access(principal,u['organization_id'])
        conn.execute('UPDATE users SET deleted_at=? WHERE id=?',(utcnow(),user_id))
        conn.execute('DELETE FROM web_sessions WHERE user_id=?',(user_id,))
        audit(conn,principal.username,'user_deleted',organization_id=u['organization_id'],object_type='user',object_id=user_id,detail=u['username'])
    return RedirectResponse('/users',status_code=303)


@app.post('/admin/policies/{policy_id}/disable')
def disable_policy(policy_id:int, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        p=conn.execute('SELECT * FROM scoped_policies WHERE id=?',(policy_id,)).fetchone()
        if not p: raise HTTPException(status_code=404,detail='Policy not found')
        if p['scope_type']=='global' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Global administrator required')
        if p['organization_id'] is not None: require_org_access(principal,p['organization_id'])
        if not p['active']:
            return RedirectResponse('/policies',status_code=303)
        conn.execute('UPDATE scoped_policies SET active=0,disabled_at=?,disabled_by=? WHERE id=?',(utcnow(),principal.username,policy_id))

        if p['action']=='allow':
            rows=conn.execute("SELECT DISTINCT device_id,policy_id FROM approved_components WHERE policy_definition_id=? AND status='approved' AND policy_id IS NOT NULL",(policy_id,)).fetchall()
            for r in rows:
                if re.fullmatch(r'[0-9A-Fa-f-]{36}',r['policy_id'] or ''):
                    conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",(r['device_id'],'revoke_approval',json.dumps({'policy_id':r['policy_id'],'requested_by':principal.username,'scoped_policy_id':policy_id}),'pending',utcnow()))
                    conn.execute("UPDATE approved_components SET status='revoking' WHERE device_id=? AND policy_id=? AND status='approved'",(r['device_id'],r['policy_id']))
                    conn.execute("UPDATE approved_applications SET status='revoking' WHERE device_id=? AND policy_id=? AND status='approved'",(r['device_id'],r['policy_id']))
            detail=f'allow revokes queued={len(rows)}'
        else:
            blocks=conn.execute("SELECT * FROM blocked_applications WHERE policy_definition_id=? AND status IN ('blocking','blocked','failed','unblocking')",(policy_id,)).fetchall()
            queued=0; canceled=0; processing=0
            for b in blocks:
                if b['status']=='blocking':
                    pattern=f'%"block_id": {b["id"]}%'
                    cmd=conn.execute("SELECT * FROM commands WHERE device_id=? AND command_type='block_file' AND payload LIKE ? AND status IN ('pending','processing') ORDER BY id DESC LIMIT 1",(b['device_id'],pattern)).fetchone()
                    if cmd and cmd['status']=='pending':
                        conn.execute("UPDATE commands SET status='canceled',completed_at=?,result='Canceled because scoped block was disabled before endpoint processing.' WHERE id=?",(utcnow(),cmd['id']))
                        conn.execute("UPDATE blocked_applications SET status='unblocked',unblocked_at=?,unblocked_by=?,note=? WHERE id=?",(utcnow(),principal.username,'Scoped block disabled before deny policy installation.',b['id']))
                        canceled+=1
                    elif cmd and cmd['status']=='processing':
                        processing+=1
                    else:
                        conn.execute("UPDATE blocked_applications SET status='unblocked',unblocked_at=?,unblocked_by=? WHERE id=?",(utcnow(),principal.username,b['id']))
                elif b['status']=='blocked' and re.fullmatch(r'[0-9A-Fa-f-]{36}',b['policy_id'] or ''):
                    conn.execute("INSERT INTO commands(device_id,command_type,payload,status,created_at) VALUES(?,?,?,?,?)",(b['device_id'],'unblock_file',json.dumps({'block_id':b['id'],'policy_id':b['policy_id'],'requested_by':principal.username,'scoped_policy_id':policy_id}),'pending',utcnow()))
                    conn.execute("UPDATE blocked_applications SET status='unblocking' WHERE id=?",(b['id'],))
                    queued+=1
                elif b['status']=='failed':
                    conn.execute("UPDATE blocked_applications SET status='unblocked',unblocked_at=?,unblocked_by=?,note=? WHERE id=?",(utcnow(),principal.username,'Scoped block disabled after deny generation failure.',b['id']))
            detail=f'block removals queued={queued}; pending canceled={canceled}; processing awaiting cleanup={processing}'
        audit(conn,principal.username,'scoped_policy_disabled',organization_id=p['organization_id'],object_type='scoped_policy',object_id=policy_id,detail=detail)
    return RedirectResponse('/policies',status_code=303)



@app.post('/admin/policies/{policy_id}/delete')
def delete_policy(policy_id:int, principal:Principal=Depends(admin_auth)):
    require_org_admin(principal)
    with db() as conn:
        p=conn.execute('SELECT * FROM scoped_policies WHERE id=? AND deleted_at IS NULL',(policy_id,)).fetchone()
        if not p: raise HTTPException(status_code=404,detail='Policy not found')
        if p['scope_type']=='global' and not principal.can_manage_global: raise HTTPException(status_code=403,detail='Global administrator required')
        if p['organization_id'] is not None: require_org_access(principal,p['organization_id'])
        if p['active']: raise HTTPException(status_code=400,detail='Disable the policy before deleting it.')
        active_commands=conn.execute("SELECT COUNT(*) n FROM commands WHERE status IN ('pending','processing') AND payload LIKE ?",(f'%\"scoped_policy_id\": {policy_id}%',)).fetchone()['n']
        active_allow=conn.execute("SELECT COUNT(*) n FROM approved_components WHERE policy_definition_id=? AND status IN ('approved','revoking')",(policy_id,)).fetchone()['n']
        active_allow += conn.execute("SELECT COUNT(*) n FROM approved_applications WHERE policy_definition_id=? AND status IN ('approved','revoking')",(policy_id,)).fetchone()['n']
        active_block=conn.execute("SELECT COUNT(*) n FROM blocked_applications WHERE policy_definition_id=? AND status IN ('blocking','blocked','unblocking')",(policy_id,)).fetchone()['n']
        if active_commands or active_allow or active_block:
            raise HTTPException(status_code=409,detail='Endpoint cleanup is still in progress for this policy. Wait for revoke/unblock operations to complete, then delete it.')
        conn.execute('UPDATE scoped_policies SET deleted_at=?,deleted_by=? WHERE id=?',(utcnow(),principal.username,policy_id))
        audit(conn,principal.username,'scoped_policy_deleted',organization_id=p['organization_id'],object_type='scoped_policy',object_id=policy_id,detail=f"{p['action']} {p['name']}")
    return RedirectResponse('/policies',status_code=303)
