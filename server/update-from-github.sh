#!/usr/bin/env bash
set -euo pipefail

REPO="${APPCONTROL_GITHUB_REPO:-flattery103/AppControlManager}"
API_BASE="${APPCONTROL_GITHUB_API_BASE:-https://api.github.com/repos/${REPO}}"
BASE="/opt/appcontrol-manager"
HEALTH_URL="${APPCONTROL_HEALTH_URL:-http://127.0.0.1:8090/health}"
MODE="${1:---check}"
FORCE=0
[ "${2:-}" = "--force" ] && FORCE=1

usage() {
  cat <<USAGE
Usage: $0 --check
       $0 --install [--force]

Checks GitHub Releases for ${REPO}. --install downloads the latest AppControl
Manager source ZIP and SHA256, verifies them, runs the packaged server upgrade,
and confirms the local /health version afterward.

Optional environment variables:
  APPCONTROL_GITHUB_REPO   GitHub owner/repo (default: ${REPO})
  APPCONTROL_GITHUB_TOKEN  Optional GitHub token, useful if the repo becomes private
  APPCONTROL_HEALTH_URL    Local health endpoint (default: ${HEALTH_URL})
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
  echo "Make sure the repository has at least one published GitHub Release." >&2
  exit 1
fi

readarray -t release_info < <(python3 - "$release_json" <<'PY'
import json, sys
p=sys.argv[1]
with open(p, encoding='utf-8') as f:
    r=json.load(f)
tag=str(r.get('tag_name') or '').strip()
version=tag[1:] if tag.lower().startswith('v') else tag
assets={a.get('name'): a.get('url') for a in r.get('assets', [])}
zip_name=f"AppControlManager-{version}-source.zip"
sha_name=zip_name+".sha256"
print(version)
print(assets.get(zip_name, ''))
print(assets.get(sha_name, ''))
print(r.get('html_url',''))
PY
)

LATEST="${release_info[0]:-}"
ZIP_URL="${release_info[1]:-}"
SHA_URL="${release_info[2]:-}"
RELEASE_URL="${release_info[3]:-}"

if [ -z "$LATEST" ]; then
  echo "Latest GitHub release does not contain a usable version tag." >&2
  exit 1
fi

CURRENT=$(python3 - "$HEALTH_URL" <<'PY'
import json, sys, urllib.request
url=sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=4) as r:
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

same=0
[ "$CURRENT" = "$LATEST" ] && same=1
if [ "$MODE" = "--check" ]; then
  if [ "$same" -eq 1 ]; then
    echo "Status:           Up to date"
  else
    echo "Status:           Update available"
  fi
  exit 0
fi

if [ "$same" -eq 1 ] && [ "$FORCE" -ne 1 ]; then
  echo "Server is already at ${LATEST}. Use --install --force to reinstall it."
  exit 0
fi

if [ -z "$ZIP_URL" ] || [ -z "$SHA_URL" ]; then
  echo "Release v${LATEST} is missing the required source ZIP or SHA256 asset." >&2
  echo "Expected assets:" >&2
  echo "  AppControlManager-${LATEST}-source.zip" >&2
  echo "  AppControlManager-${LATEST}-source.zip.sha256" >&2
  exit 1
fi

ZIP="$TMP/AppControlManager-${LATEST}-source.zip"
SHA="$ZIP.sha256"
echo "Downloading release assets..."
asset_args=( -fsSL -H "Accept: application/octet-stream" -H "X-GitHub-Api-Version: 2022-11-28" )
if [ -n "${APPCONTROL_GITHUB_TOKEN:-}" ]; then
  asset_args+=( -H "Authorization: Bearer ${APPCONTROL_GITHUB_TOKEN}" )
fi
curl "${asset_args[@]}" "$ZIP_URL" -o "$ZIP"
curl "${asset_args[@]}" "$SHA_URL" -o "$SHA"

(
  cd "$TMP"
  sha256sum -c "$(basename "$SHA")"
)

echo "Extracting AppControl Manager ${LATEST}..."
unzip -q "$ZIP" -d "$TMP/extracted"
SERVER_DIR="$TMP/extracted/AppControlManager-${LATEST}/server"
if [ ! -x "$SERVER_DIR/upgrade-server.sh" ]; then
  chmod +x "$SERVER_DIR/upgrade-server.sh" 2>/dev/null || true
fi
if [ ! -f "$SERVER_DIR/upgrade-server.sh" ]; then
  echo "Release package is missing server/upgrade-server.sh." >&2
  exit 1
fi

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
