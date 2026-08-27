#!/usr/bin/env bash
set -euo pipefail
NEW_BASE=/opt/appcontrol-manager
NEW_ENV=/etc/appcontrol-manager.env
NEW_SERVICE=appcontrol-manager
OLD_BASE=/opt/appguard-poc
OLD_ENV=/etc/appguard-poc.env
OLD_SERVICE=appguard-poc

if [ ! -f "$NEW_ENV" ] && [ ! -f "$OLD_ENV" ]; then
  echo "Existing AppControl Manager/AppGuard server installation not found. Run ./install-server.sh instead." >&2
  exit 1
fi

SOURCE_ENV="$NEW_ENV"
[ -f "$SOURCE_ENV" ] || SOURCE_ENV="$OLD_ENV"
SOURCE_BASE="$NEW_BASE"
[ -d "$SOURCE_BASE" ] || SOURCE_BASE="$OLD_BASE"

# Find the currently active database before any migration and create a timestamped backup.
DB=$(grep -E '^(APPCONTROL_DB|APPGUARD_DB)=' "$SOURCE_ENV" | tail -1 | cut -d= -f2- || true)
[ -n "${DB:-}" ] || DB="$SOURCE_BASE/appguard.db"
if [ -f "$DB" ]; then
  BACKUP_DIR="$SOURCE_BASE/backups"
  sudo mkdir -p "$BACKUP_DIR"
  STAMP=$(date +%Y%m%d-%H%M%S)
  BACKUP="$BACKUP_DIR/$(basename "$DB").$STAMP"
  sudo cp -a "$DB" "$BACKUP"
  echo "Database backup created: $BACKUP"
fi

sudo mkdir -p "$NEW_BASE" "$NEW_BASE/releases"

# Migrate the legacy database to the new branded path only when it lived under /opt/appguard-poc.
TARGET_DB="$DB"
if [[ "$DB" == "$OLD_BASE"/* ]]; then
  TARGET_DB="$NEW_BASE/appcontrol-manager.db"
  if [ ! -f "$TARGET_DB" ]; then
    sudo cp -a "$DB" "$TARGET_DB"
    echo "Database migrated to: $TARGET_DB"
  fi
fi

# Create the new environment file from either the current branded config or the legacy one.
if [ ! -f "$NEW_ENV" ]; then
  ENROLL=$(grep -E '^(APPCONTROL_ENROLLMENT_TOKEN|APPGUARD_ENROLLMENT_TOKEN)=' "$SOURCE_ENV" | tail -1 | cut -d= -f2- || true)
  ADMIN_USER=$(grep -E '^(APPCONTROL_ADMIN_USER|APPGUARD_ADMIN_USER)=' "$SOURCE_ENV" | tail -1 | cut -d= -f2- || true)
  ADMIN_PASS=$(grep -E '^(APPCONTROL_ADMIN_PASSWORD|APPGUARD_ADMIN_PASSWORD)=' "$SOURCE_ENV" | tail -1 | cut -d= -f2- || true)
  sudo tee "$NEW_ENV" >/dev/null <<ENV
APPCONTROL_ENROLLMENT_TOKEN=${ENROLL:-CHANGE-ME}
APPCONTROL_ADMIN_USER=${ADMIN_USER:-admin}
APPCONTROL_ADMIN_PASSWORD=${ADMIN_PASS:-ChangeMeNow!}
APPCONTROL_DB=$TARGET_DB
APPCONTROL_RELEASE_DIR=$NEW_BASE/releases
APPCONTROL_SESSION_HOURS=12
APPCONTROL_COOKIE_SECURE=0
APPCONTROL_OFFLINE_ATTENTION_DAYS=7
APPCONTROL_STALE_DEVICE_DAYS=30
ENV
  sudo chmod 600 "$NEW_ENV"
  echo "Created $NEW_ENV from the existing server configuration."
fi

if ! grep -q '^APPCONTROL_SESSION_HOURS=' "$NEW_ENV"; then
  echo 'APPCONTROL_SESSION_HOURS=12' | sudo tee -a "$NEW_ENV" >/dev/null
fi
if ! grep -q '^APPCONTROL_COOKIE_SECURE=' "$NEW_ENV"; then
  echo 'APPCONTROL_COOKIE_SECURE=0' | sudo tee -a "$NEW_ENV" >/dev/null
fi
if ! grep -q '^APPCONTROL_RELEASE_DIR=' "$NEW_ENV"; then
  echo 'APPCONTROL_RELEASE_DIR=/opt/appcontrol-manager/releases' | sudo tee -a "$NEW_ENV" >/dev/null
fi
if ! grep -q '^APPCONTROL_OFFLINE_ATTENTION_DAYS=' "$NEW_ENV"; then
  echo 'APPCONTROL_OFFLINE_ATTENTION_DAYS=7' | sudo tee -a "$NEW_ENV" >/dev/null
fi
if ! grep -q '^APPCONTROL_STALE_DEVICE_DAYS=' "$NEW_ENV"; then
  echo 'APPCONTROL_STALE_DEVICE_DAYS=30' | sudo tee -a "$NEW_ENV" >/dev/null
fi

sudo cp app.py release_management.py requirements.txt "$NEW_BASE/"
sudo install -m 0755 update-from-github.sh "$NEW_BASE/update-from-github.sh"
sudo install -m 0755 import-agent-release.py "$NEW_BASE/import-agent-release.py"
if [ ! -x "$NEW_BASE/venv/bin/python" ]; then
  sudo python3 -m venv "$NEW_BASE/venv"
fi
sudo "$NEW_BASE/venv/bin/pip" install -r "$NEW_BASE/requirements.txt"

sudo tee /etc/systemd/system/$NEW_SERVICE.service >/dev/null <<'UNIT'
[Unit]
Description=AppControl Manager Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/appcontrol-manager
EnvironmentFile=/etc/appcontrol-manager.env
ExecStart=/opt/appcontrol-manager/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8090
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
UNIT

if systemctl list-unit-files | grep -q '^appguard-poc.service'; then
  sudo systemctl stop "$OLD_SERVICE" 2>/dev/null || true
  sudo systemctl disable "$OLD_SERVICE" 2>/dev/null || true
fi
sudo systemctl daemon-reload
sudo systemctl enable "$NEW_SERVICE" >/dev/null
sudo systemctl restart "$NEW_SERVICE"
sudo systemctl --no-pager status "$NEW_SERVICE" || true

echo
echo "AppControl Manager server upgraded to 0.16.0 and restarted."
echo "The legacy /opt/appguard-poc and /etc/appguard-poc.env files were left in place for rollback, but appguard-poc.service is disabled."
