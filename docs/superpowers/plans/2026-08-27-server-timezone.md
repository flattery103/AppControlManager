# AppControl Manager 0.16.3 Server Timezone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store all server timestamps in UTC as today, but render human-facing timestamps in a clean format using a global IANA timezone configured from a new Settings page.

**Architecture:** Add one additive `server_settings` key/value table and a global-admin Settings page. Load/validate the `display_timezone` setting using Python `zoneinfo.ZoneInfo`; `display_time()` converts aware UTC input into that zone at render time and formats it as `Aug 27, 2026 7:04 PM`. Agent/API storage and machine-to-machine timestamp contracts stay UTC and unchanged.

**Tech Stack:** FastAPI/Python 3 standard library `zoneinfo`, SQLite, existing server HTML helper functions and unittest suite.

**Spec:** `docs/superpowers/specs/2026-08-27-approval-pipeline-design.md` section 9.

## Global Constraints

- Internal timestamp storage remains UTC ISO-8601.
- The setting is server-wide and editable only by `global_admin`.
- Use an IANA identifier, not a fixed UTC offset, so daylight-saving changes are automatic.
- Default to `UTC` if the setting is missing/invalid.
- Existing agent APIs keep raw UTC timestamps; only human-facing server pages/reports are localized.
- Additive schema only; 0.16.2 must ignore the extra table if rolled back.
- Target full display: `Aug 27, 2026 7:04 PM`.
- Target compact display where space is constrained: `Aug 27 7:04 PM`.

---

### Task 1: Write timezone regression tests first

**Files:**
- Create: `server/tests/test_0163_timezone.py`
- Modify later: `server/app.py`

**Interfaces:**
- Defines `format_display_time(value, timezone_name, compact=False) -> str` as the pure testable conversion primitive.
- Defines persistent setting key `display_timezone`.

- [ ] **Step 1: Write failing tests**

```python
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / 'server'
if str(SERVER) not in sys.path:
    sys.path.insert(0, str(SERVER))
os.environ['APPCONTROL_DB'] = str(Path(tempfile.gettempdir()) / 'acm-0163-timezone.db')

import app


class TimezoneTests(unittest.TestCase):
    def test_format_display_time_uses_dst_aware_iana_timezone(self):
        self.assertEqual(app.format_display_time('2026-01-15T18:00:00+00:00', 'America/Chicago'), 'Jan 15, 2026 12:00 PM')
        self.assertEqual(app.format_display_time('2026-07-15T18:00:00+00:00', 'America/Chicago'), 'Jul 15, 2026 1:00 PM')

    def test_invalid_timezone_falls_back_to_utc(self):
        self.assertEqual(app.format_display_time('2026-08-28T00:04:00+00:00', 'Not/AZone'), 'Aug 28, 2026 12:04 AM')

    def test_server_settings_table_is_additive(self):
        app.init_db()
        with app.db() as conn:
            row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='server_settings'").fetchone()
            self.assertIsNotNone(row)

    def test_utcnow_remains_utc_storage(self):
        value = app.utcnow()
        self.assertIn('+00:00', value)

    def test_settings_nav_and_routes_exist(self):
        text = (SERVER / 'app.py').read_text(encoding='utf-8')
        self.assertIn("('/settings','Settings'", text)
        self.assertIn("@app.get('/settings'", text)
        self.assertIn("@app.post('/admin/settings/timezone'", text)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run and verify RED**

```bash
python -m unittest server.tests.test_0163_timezone -v
```

Expected: FAIL because `format_display_time`, table, and routes do not exist.

- [ ] **Step 3: Commit RED tests**

```bash
git add server/tests/test_0163_timezone.py
git commit -m "test: define server timezone behavior"
```

---

### Task 2: Add additive server settings storage and timezone validation

**Files:**
- Modify: `server/app.py`
- Test: `server/tests/test_0163_timezone.py`

**Interfaces:**
- `get_server_setting(conn, key, default) -> str`
- `set_server_setting(conn, key, value, actor) -> None`
- `validated_timezone_name(value) -> str`
- `format_display_time(value, timezone_name, compact=False) -> str`

- [ ] **Step 1: Add `zoneinfo` import and schema**

At imports:

```python
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
```

In `init_db()`:

```sql
CREATE TABLE IF NOT EXISTS server_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT
);
```

Do not alter/delete existing timestamp columns.

- [ ] **Step 2: Implement pure timezone formatting**

```python
def validated_timezone_name(value: Optional[str]) -> str:
    candidate = (value or 'UTC').strip() or 'UTC'
    try:
        ZoneInfo(candidate)
        return candidate
    except (ZoneInfoNotFoundError, ValueError):
        return 'UTC'


def format_display_time(value: Optional[str], timezone_name: str, compact: bool = False) -> str:
    if not value:
        return ''
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone(ZoneInfo(validated_timezone_name(timezone_name)))
        clock = local.strftime('%I:%M %p').lstrip('0')
        if compact:
            return f"{local.strftime('%b')} {local.day} {clock}"
        return f"{local.strftime('%b')} {local.day}, {local.year} {clock}"
    except Exception:
        return value
```

- [ ] **Step 3: Implement settings get/set**

`display_timezone` defaults to `UTC`. `set_server_setting` uses UPSERT and `utcnow()` for its audit metadata.

- [ ] **Step 4: Add a small process cache for render efficiency**

Do not open SQLite once per table cell. Maintain:

```python
_DISPLAY_TIMEZONE = 'UTC'
```

Load it at startup immediately after `init_db()`. Update it synchronously after a successful settings POST. `display_time(value, compact=False)` delegates to `format_display_time(value, _DISPLAY_TIMEZONE, compact)`.

- [ ] **Step 5: Run tests and commit**

```bash
python -m unittest server.tests.test_0163_timezone -v
git add server/app.py server/tests/test_0163_timezone.py
git commit -m "feat: add DST-aware server display timezone"
```

---

### Task 3: Add the global Settings page and clean timestamp presentation

**Files:**
- Modify: `server/app.py`
- Test: `server/tests/test_0163_timezone.py`

**Interfaces:**
- `GET /settings` — global-admin page.
- `POST /admin/settings/timezone` — validates IANA ID, persists, audits, updates process cache.

- [ ] **Step 1: Add RED authorization/UI tests**

Use FastAPI TestClient if already available in requirements/tests; otherwise source-level assertions plus direct route function invocation. Require:

```text
Settings nav link only in global administration
current timezone shown
IANA timezone input required
success notice after save
```

- [ ] **Step 2: Implement nav entry**

Only under `principal.can_manage_global`:

```python
administration.append(('/settings','Settings','⚙'))
```

- [ ] **Step 3: Implement Settings page**

Use a text input with `list='timezone-list'` and common IANA choices:

```text
UTC
America/New_York
America/Chicago
America/Denver
America/Phoenix
America/Los_Angeles
America/Anchorage
Pacific/Honolulu
```

The user may enter any valid IANA timezone; do not restrict storage to only these examples.

- [ ] **Step 4: Implement POST validation**

Reject invalid identifiers with HTTP 400 and a clear message. On success:

```python
set_server_setting(conn, 'display_timezone', tz_name, principal.username)
audit(conn, principal.username, 'server_timezone_changed', object_type='server_setting', object_id='display_timezone', detail=tz_name)
_DISPLAY_TIMEZONE = tz_name
```

Redirect to `/settings?saved=1`.

- [ ] **Step 5: Apply the clean formatter consistently**

The existing `display_time()` call sites automatically pick up the new format. Inspect human-facing raw timestamps and replace at least these known exceptions:

- Server Updates `release.published_at` trend.
- Any visible table/detail field that directly interpolates `created_at`, `updated_at`, `completed_at`, `occurred_at`, `last_seen`, `decided_at`, or `last_login` without `display_time()`.

Do **not** localize timestamps in agent JSON APIs or DB writes.

- [ ] **Step 6: Add DST/format regression test and run all server tests**

```bash
python -m unittest server.tests.test_0163_timezone -v
python -m unittest discover -s server/tests -v
python -m py_compile server/app.py
```

- [ ] **Step 7: Commit**

```bash
git add server/app.py server/tests/test_0163_timezone.py
git commit -m "feat: add configurable server timezone settings"
```

---

## Acceptance Test

After 0.16.3 server update:

1. Open **Settings** as global admin.
2. Set `America/Chicago`.
3. Confirm a known UTC timestamp around the current date renders in Central daylight/standard time as appropriate.
4. Verify visible device Last Seen, approval request times, activity/history, command history, update history, enrollment-token Last Used, user Last Login, and server update publication times use the clean local format.
5. Restart `appcontrol-manager`; confirm the configured timezone persists and the UI still renders locally.
6. Change to another IANA zone, refresh, and confirm displayed values change while DB values remain original UTC strings.
7. If the 0.16.3 server is rolled back to 0.16.2, confirm the extra `server_settings` table does not prevent 0.16.2 startup.
