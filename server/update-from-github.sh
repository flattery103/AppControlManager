#!/usr/bin/env bash
set -euo pipefail

BASE="/opt/appcontrol-manager"
ENVFILE="/etc/appcontrol-manager.env"
HEALTH_URL="${APPCONTROL_HEALTH_URL:-http://127.0.0.1:8090/health}"
MODE="${1:---check}"
FORCE=0
[ "${2:-}" = "--force" ] && FORCE=1

command -v python3 >/dev/null 2>&1 || { echo "Required command not found: python3" >&2; exit 1; }

env_value() {
  local name="$1"
  [ -f "$ENVFILE" ] || return 0
  python3 - "$ENVFILE" "$name" <<'PY'
import sys
path, name = sys.argv[1], sys.argv[2]
value = ''
try:
    with open(path, encoding='utf-8') as f:
        for raw in f:
            line=raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key,val=line.split('=',1)
            if key.strip()==name:
                value=val.strip()
                if len(value)>=2 and value[0]==value[-1] and value[0] in "'\"":
                    value=value[1:-1]
except OSError:
    pass
print(value)
PY
}

if [ -z "${APPCONTROL_GITHUB_REPO:-}" ]; then APPCONTROL_GITHUB_REPO="$(env_value APPCONTROL_GITHUB_REPO)"; fi
if [ -z "${APPCONTROL_GITHUB_API_BASE:-}" ]; then APPCONTROL_GITHUB_API_BASE="$(env_value APPCONTROL_GITHUB_API_BASE)"; fi
if [ -z "${APPCONTROL_GITHUB_TOKEN:-}" ]; then APPCONTROL_GITHUB_TOKEN="$(env_value APPCONTROL_GITHUB_TOKEN)"; fi

REPO="${APPCONTROL_GITHUB_REPO:-flattery103/AppControlManager}"
API_BASE="${APPCONTROL_GITHUB_API_BASE:-https://api.github.com/repos/${REPO}}"

usage() {
  cat <<USAGE
Usage: $0 --check
       $0 --install [--force]

Checks GitHub Releases for ${REPO}. --install downloads and verifies the latest
server source plus matching Windows agent/installer assets, runs the packaged
server upgrade, confirms /health, and imports the matching stable agent release.

Optional environment variables (also read from /etc/appcontrol-manager.env):
  APPCONTROL_GITHUB_REPO      GitHub owner/repo (default: ${REPO})
  APPCONTROL_GITHUB_TOKEN     Optional GitHub token for a private repository
  APPCONTROL_GITHUB_API_BASE  Optional GitHub API base override
  APPCONTROL_HEALTH_URL       Local health endpoint (default: ${HEALTH_URL})
USAGE
}

case "$MODE" in
  --check|--install) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

for cmd in curl python3 sha256sum unzip; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Required command not found: $cmd" >&2; exit 1; }
done

curl_args=(
  -fsSL
  -H "Accept: application/vnd.github+json"
  -H "X-GitHub-Api-Version: 2022-11-28"
)
if [ -n "${APPCONTROL_GITHUB_TOKEN:-}" ]; then
  curl_args+=( -H "Authorization: Bearer ${APPCONTROL_GITHUB_TOKEN}" )
fi

TMP=$(mktemp -d /tmp/appcontrol-github-update.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

release_json="$TMP/release.json"
if ! curl "${curl_args[@]}" "${API_BASE}/releases/latest" -o "$release_json"; then
  echo "Unable to read the latest GitHub release for ${REPO}." >&2
  echo "Make sure the repository has at least one published GitHub Release and that private-repository credentials are configured." >&2
  exit 1
fi

readarray -t release_info < <(python3 - "$release_json" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    r=json.load(f)
tag=str(r.get('tag_name') or '').strip()
version=tag[1:] if tag.lower().startswith('v') else tag
assets={str(a.get('name') or ''): str(a.get('url') or '') for a in r.get('assets', [])}
names=[
    f"AppControlManager-{version}-source.zip",
    f"AppControlManager-{version}-source.zip.sha256",
    f"AppControlManager-Agent-{version}-win-x64.zip",
    f"AppControlManager-Agent-{version}-win-x64.zip.sha256",
    f"AppControlManager-Installer-{version}.exe",
    f"AppControlManager-Installer-{version}.exe.sha256",
]
print(version)
print(r.get('html_url',''))
for name in names:
    print(assets.get(name,''))
PY
)

LATEST="${release_info[0]:-}"
RELEASE_URL="${release_info[1]:-}"
ZIP_URL="${release_info[2]:-}"
SHA_URL="${release_info[3]:-}"
AGENT_URL="${release_info[4]:-}"
AGENT_SHA_URL="${release_info[5]:-}"
INSTALLER_URL="${release_info[6]:-}"
INSTALLER_SHA_URL="${release_info[7]:-}"

if [ -z "$LATEST" ]; then
  echo "Latest GitHub release does not contain a usable version tag." >&2
  exit 1
fi

CURRENT=$(python3 - "$HEALTH_URL" <<'PY'
import json, sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=4) as r:
        data=json.load(r)
    print(str(data.get('version') or 'unknown'))
except Exception:
    print('unknown')
PY
)

echo "Repository:      ${REPO}"
echo "Current server:  ${CURRENT}"
echo "Latest release:  ${LATEST}"
[ -n "$RELEASE_URL" ] && echo "Release:         ${RELEASE_URL}"

missing=0
for pair in \
  "source ZIP:$ZIP_URL" \
  "source SHA256:$SHA_URL" \
  "agent ZIP:$AGENT_URL" \
  "agent SHA256:$AGENT_SHA_URL" \
  "installer EXE:$INSTALLER_URL" \
  "installer SHA256:$INSTALLER_SHA_URL"; do
  label="${pair%%:*}"; value="${pair#*:}"
  if [ -n "$value" ]; then
    echo "Asset ${label}: available"
  else
    echo "Asset ${label}: MISSING"
    missing=1
  fi
done

same=0
[ "$CURRENT" = "$LATEST" ] && same=1
if [ "$MODE" = "--check" ]; then
  if [ "$same" -eq 1 ]; then
    echo "Status:           Up to date"
  else
    echo "Status:           Update available"
  fi
  [ "$missing" -eq 0 ] || exit 1
  exit 0
fi

if [ "$same" -eq 1 ] && [ "$FORCE" -ne 1 ]; then
  echo "Server is already at ${LATEST}. Use --install --force to reinstall it."
  exit 0
fi

if [ "$missing" -ne 0 ]; then
  echo "Release v${LATEST} is missing one or more required release assets." >&2
  echo "Expected assets:" >&2
  echo "  AppControlManager-${LATEST}-source.zip" >&2
  echo "  AppControlManager-${LATEST}-source.zip.sha256" >&2
  echo "  AppControlManager-Agent-${LATEST}-win-x64.zip" >&2
  echo "  AppControlManager-Agent-${LATEST}-win-x64.zip.sha256" >&2
  echo "  AppControlManager-Installer-${LATEST}.exe" >&2
  echo "  AppControlManager-Installer-${LATEST}.exe.sha256" >&2
  exit 1
fi

ZIP="$TMP/AppControlManager-${LATEST}-source.zip"
SHA="$TMP/AppControlManager-${LATEST}-source.zip.sha256"
AGENT_ZIP="$TMP/AppControlManager-Agent-${LATEST}-win-x64.zip"
AGENT_SHA="$TMP/AppControlManager-Agent-${LATEST}-win-x64.zip.sha256"
INSTALLER="$TMP/AppControlManager-Installer-${LATEST}.exe"
INSTALLER_SHA="$TMP/AppControlManager-Installer-${LATEST}.exe.sha256"

echo "Downloading release assets..."
asset_args=( -fsSL -H "Accept: application/octet-stream" -H "X-GitHub-Api-Version: 2022-11-28" )
if [ -n "${APPCONTROL_GITHUB_TOKEN:-}" ]; then
  asset_args+=( -H "Authorization: Bearer ${APPCONTROL_GITHUB_TOKEN}" )
fi
curl "${asset_args[@]}" "$ZIP_URL" -o "$ZIP"
curl "${asset_args[@]}" "$SHA_URL" -o "$SHA"
curl "${asset_args[@]}" "$AGENT_URL" -o "$AGENT_ZIP"
curl "${asset_args[@]}" "$AGENT_SHA_URL" -o "$AGENT_SHA"
curl "${asset_args[@]}" "$INSTALLER_URL" -o "$INSTALLER"
curl "${asset_args[@]}" "$INSTALLER_SHA_URL" -o "$INSTALLER_SHA"

(
  cd "$TMP"
  sha256sum -c "$(basename "$SHA")"
  sha256sum -c "$(basename "$AGENT_SHA")"
  sha256sum -c "$(basename "$INSTALLER_SHA")"
)

echo "Extracting AppControl Manager ${LATEST}..."
unzip -q "$ZIP" -d "$TMP/extracted"
# GitHub source archives are built on a Windows runner. Normalize shell scripts defensively
# before executing them so an accidental CRLF checkout/archive cannot break Linux shebangs.
find "$TMP/extracted" -type f -name '*.sh' -exec sed -i 's/\r$//' {} +
SERVER_DIR="$TMP/extracted/AppControlManager-${LATEST}/server"
if [ ! -f "$SERVER_DIR/upgrade-server.sh" ]; then
  echo "Release package is missing server/upgrade-server.sh." >&2
  exit 1
fi
chmod +x "$SERVER_DIR/upgrade-server.sh" 2>/dev/null || true

echo "Running packaged server upgrade..."
(
  cd "$SERVER_DIR"
  ./upgrade-server.sh
)

echo "Waiting for AppControl Manager ${LATEST} health check..."
ok=0
for _ in $(seq 1 30); do
  got=$(python3 - "$HEALTH_URL" <<'PY'
import json, sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=3) as r:
        d=json.load(r)
    print(str(d.get('version') or ''))
except Exception:
    print('')
PY
)
  if [ "$got" = "$LATEST" ]; then
    ok=1
    break
  fi
  sleep 2
done

if [ "$ok" -ne 1 ]; then
  echo "Upgrade command finished, but /health did not report ${LATEST}." >&2
  echo "Check: systemctl status appcontrol-manager --no-pager" >&2
  exit 1
fi

echo "AppControl Manager server successfully upgraded to ${LATEST}."

DB_PATH="${APPCONTROL_DB:-$(env_value APPCONTROL_DB)}"
RELEASE_DIR="${APPCONTROL_RELEASE_DIR:-$(env_value APPCONTROL_RELEASE_DIR)}"
[ -n "$DB_PATH" ] || DB_PATH="$BASE/appcontrol-manager.db"
[ -n "$RELEASE_DIR" ] || RELEASE_DIR="$BASE/releases"
IMPORTER="$BASE/import-agent-release.py"
PYTHON="$BASE/venv/bin/python"
if [ ! -x "$PYTHON" ] || [ ! -f "$IMPORTER" ]; then
  echo "Server update succeeded, but the agent release importer is not installed." >&2
  exit 1
fi

echo "Importing matching Agent release ${LATEST} into AppControl Manager..."
"$PYTHON" "$IMPORTER" \
  --version "$LATEST" \
  --package "$AGENT_ZIP" \
  --installer "$INSTALLER" \
  --channel stable \
  --db "$DB_PATH" \
  --release-dir "$RELEASE_DIR" \
  --notes "Imported automatically from GitHub Release v${LATEST}."

echo "Agent release ${LATEST} is available for managed deployment."
