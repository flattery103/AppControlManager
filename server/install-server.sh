#!/usr/bin/env bash
set -euo pipefail
BASE=/opt/appcontrol-manager
ENVFILE=/etc/appcontrol-manager.env
SERVICE=appcontrol-manager
sudo mkdir -p "$BASE" "$BASE/releases"
sudo cp app.py requirements.txt "$BASE/"
sudo install -m 0755 update-from-github.sh "$BASE/update-from-github.sh"
sudo python3 -m venv "$BASE/venv"
sudo "$BASE/venv/bin/pip" install -r "$BASE/requirements.txt"
if [ ! -f "$ENVFILE" ]; then
  ENROLL=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
  ADMINPASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(20))')
  sudo tee "$ENVFILE" >/dev/null <<ENV
APPCONTROL_ENROLLMENT_TOKEN=$ENROLL
APPCONTROL_ADMIN_USER=admin
APPCONTROL_ADMIN_PASSWORD=$ADMINPASS
APPCONTROL_DB=$BASE/appcontrol-manager.db
APPCONTROL_RELEASE_DIR=$BASE/releases
APPCONTROL_SESSION_HOURS=12
APPCONTROL_COOKIE_SECURE=0
APPCONTROL_OFFLINE_ATTENTION_DAYS=7
APPCONTROL_STALE_DEVICE_DAYS=30
ENV
  sudo chmod 600 "$ENVFILE"
  echo "Created $ENVFILE with generated credentials."
fi
sudo tee /etc/systemd/system/$SERVICE.service >/dev/null <<'UNIT'
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
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE" >/dev/null
sudo systemctl restart "$SERVICE"
sudo systemctl --no-pager status "$SERVICE" || true
echo
echo "AppControl Manager server installed and restarted."
echo "Server is listening on 0.0.0.0:8090 (all IPv4 interfaces)."
echo "Credentials are stored in $ENVFILE"
