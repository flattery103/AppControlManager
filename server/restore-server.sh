#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || "$2" != "--confirm" ]]; then
  echo "Usage: $0 BACKUP_PATH --confirm" >&2
  exit 2
fi

backup_path="$1"
target_db="${APPCONTROL_DB:-}"
if [[ -z "$target_db" && -r /etc/appcontrol-manager.env ]]; then
  target_db=$(sed -n 's/^APPCONTROL_DB=//p' /etc/appcontrol-manager.env | tail -1)
fi
target_db="${target_db:-/opt/appcontrol-manager/appcontrol-manager.db}"
python_bin="${APPCONTROL_PYTHON:-}"
if [[ -z "$python_bin" ]]; then
  if [[ -x /opt/appcontrol-manager/venv/bin/python ]]; then python_bin=/opt/appcontrol-manager/venv/bin/python; else python_bin=python3; fi
fi

if [[ ! -f "$backup_path" ]]; then echo "Backup not found: $backup_path" >&2; exit 1; fi
"$python_bin" - "$backup_path" <<'PY'
import sqlite3, sys
with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as conn:
    result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok": raise SystemExit(f"Restore candidate integrity check failed: {result}")
PY

skip_service="${APPCONTROL_SKIP_SERVICE:-0}"
if [[ "$skip_service" != "1" ]]; then sudo systemctl stop appcontrol-manager; fi

recovery_path=""
if [[ -f "$target_db" ]]; then
  recovery_path="${target_db}.before-restore.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$target_db" "$recovery_path"
fi
mkdir -p "$(dirname "$target_db")"
temp_target="${target_db}.restore.$$"
cp "$backup_path" "$temp_target"
chmod 600 "$temp_target"
if [[ -n "$recovery_path" ]]; then chown --reference="$recovery_path" "$temp_target"; fi
mv "$temp_target" "$target_db"

if [[ "$skip_service" != "1" ]]; then
  sudo systemctl start appcontrol-manager
  curl -fsS http://127.0.0.1:8090/health >/dev/null
fi
echo "Restored AppControl Manager database: $target_db"
if [[ -n "$recovery_path" ]]; then echo "Previous database preserved: $recovery_path"; fi
