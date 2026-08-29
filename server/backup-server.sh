#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 OUTPUT_PATH" >&2
  exit 2
fi

source_db="${APPCONTROL_DB:-}"
if [[ -z "$source_db" && -r /etc/appcontrol-manager.env ]]; then
  source_db=$(sed -n 's/^APPCONTROL_DB=//p' /etc/appcontrol-manager.env | tail -1)
fi
source_db="${source_db:-/opt/appcontrol-manager/appcontrol-manager.db}"
output_path="$1"
python_bin="${APPCONTROL_PYTHON:-}"
if [[ -z "$python_bin" ]]; then
  if [[ -x /opt/appcontrol-manager/venv/bin/python ]]; then python_bin=/opt/appcontrol-manager/venv/bin/python; else python_bin=python3; fi
fi

if [[ ! -f "$source_db" ]]; then echo "Database not found: $source_db" >&2; exit 1; fi
if [[ -e "$output_path" ]]; then echo "Backup target already exists: $output_path" >&2; exit 1; fi
mkdir -p "$(dirname "$output_path")"

"$python_bin" - "$source_db" "$output_path" <<'PY'
import sqlite3, sys
source, target = sys.argv[1:3]
with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
    src.backup(dst)
    result = dst.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise SystemExit(f"Backup integrity check failed: {result}")
print(target)
PY

chmod 600 "$output_path"
echo "Verified AppControl Manager backup: $output_path"
