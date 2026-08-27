from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional


@dataclass(frozen=True)
class GitHubReleaseInfo:
    version: str
    tag_name: str
    html_url: str
    published_at: str
    notes: str
    assets: dict[str, str]

    def asset_url(self, name: str) -> Optional[str]:
        return self.assets.get(name)


@dataclass(frozen=True)
class ImportResult:
    release_id: int
    imported: bool
    package_path: str
    installer_path: str


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_release_payload(payload: Mapping[str, object]) -> GitHubReleaseInfo:
    tag = str(payload.get("tag_name") or "").strip()
    if not tag:
        raise ValueError("GitHub release does not contain a version tag.")
    version = tag[1:] if tag.lower().startswith("v") else tag
    assets: dict[str, str] = {}
    raw_assets = payload.get("assets") or []
    if isinstance(raw_assets, list):
        for item in raw_assets:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name") or "").strip()
            url = str(item.get("url") or item.get("browser_download_url") or "").strip()
            if name and url:
                assets[name] = url
    return GitHubReleaseInfo(
        version=version,
        tag_name=tag,
        html_url=str(payload.get("html_url") or ""),
        published_at=str(payload.get("published_at") or ""),
        notes=str(payload.get("body") or ""),
        assets=assets,
    )


def fetch_latest_release(
    repo: str,
    token: Optional[str] = None,
    api_base: Optional[str] = None,
    timeout: float = 6.0,
) -> GitHubReleaseInfo:
    base = (api_base or f"https://api.github.com/repos/{repo}").rstrip("/")
    request = urllib.request.Request(
        f"{base}/releases/latest",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AppControlManager-Server-Updater",
        },
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, Mapping):
        raise ValueError("GitHub release response was not an object.")
    return parse_release_payload(payload)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_sha256_file(file_path: Path | str, checksum_path: Path | str) -> str:
    file_path = Path(file_path)
    checksum_path = Path(checksum_path)
    text = checksum_path.read_text(encoding="ascii", errors="strict").strip()
    expected = text.split()[0].lower() if text else ""
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        raise ValueError(f"Invalid SHA256 file: {checksum_path}")
    actual = _sha256(file_path)
    if actual.lower() != expected:
        raise ValueError(f"SHA256 mismatch for {file_path.name}: expected {expected}, got {actual}")
    return actual


def validate_agent_package(package_path: Path | str, version: str) -> dict:
    package_path = Path(package_path)
    with zipfile.ZipFile(package_path, "r") as archive:
        try:
            raw = archive.read("agent-manifest.json")
        except KeyError as exc:
            raise ValueError("Agent package is missing agent-manifest.json.") from exc
    manifest = json.loads(raw.decode("utf-8-sig"))
    if manifest.get("product") != "AppControl Manager Agent":
        raise ValueError("Agent package manifest product is not AppControl Manager Agent.")
    if str(manifest.get("version") or "") != version:
        raise ValueError(
            f"Agent package version {manifest.get('version')!r} does not match release version {version!r}."
        )
    if manifest.get("platform") != "win-x64":
        raise ValueError("Agent package platform must be win-x64.")
    return manifest


def import_agent_release(
    *,
    db_path: Path | str,
    release_dir: Path | str,
    version: str,
    package_path: Path | str,
    installer_path: Path | str,
    notes: str,
    channel: str = "stable",
    actor: str = "github-updater",
) -> ImportResult:
    db_path = Path(db_path)
    release_dir = Path(release_dir)
    package_path = Path(package_path)
    installer_path = Path(installer_path)
    version = str(version).strip()
    channel = str(channel).strip().lower() or "stable"
    if not version:
        raise ValueError("Version is required.")
    if channel not in {"stable", "beta"}:
        raise ValueError("Channel must be stable or beta.")
    if not package_path.is_file():
        raise ValueError(f"Agent package not found: {package_path}")
    if not installer_path.is_file():
        raise ValueError(f"Installer not found: {installer_path}")
    validate_agent_package(package_path, version)

    package_sha = _sha256(package_path).upper()
    installer_sha = _sha256(installer_path).upper()
    release_dir.mkdir(parents=True, exist_ok=True)
    final_package = release_dir / package_path.name
    final_installer = release_dir / installer_path.name

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        existing = conn.execute(
            "SELECT * FROM agent_releases WHERE version=? AND channel=?",
            (version, channel),
        ).fetchone()
        if existing and not existing["deleted_at"]:
            return ImportResult(existing["id"], False, existing["file_path"], existing["installer_file_path"] or "")

        shutil.copy2(package_path, final_package)
        shutil.copy2(installer_path, final_installer)
        if existing:
            conn.execute(
                """UPDATE agent_releases
                   SET file_name=?,file_path=?,sha256=?,size_bytes=?,notes=?,active=1,created_at=?,created_by=?,
                       installer_file_name=?,installer_file_path=?,installer_sha256=?,installer_size_bytes=?,
                       deleted_at=NULL,deleted_by=NULL
                   WHERE id=?""",
                (
                    final_package.name,
                    str(final_package),
                    package_sha,
                    final_package.stat().st_size,
                    notes,
                    utcnow(),
                    actor,
                    final_installer.name,
                    str(final_installer),
                    installer_sha,
                    final_installer.stat().st_size,
                    existing["id"],
                ),
            )
            release_id = int(existing["id"])
        else:
            cur = conn.execute(
                """INSERT INTO agent_releases(
                       version,channel,file_name,file_path,sha256,size_bytes,notes,active,created_at,created_by,
                       installer_file_name,installer_file_path,installer_sha256,installer_size_bytes
                   ) VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?)""",
                (
                    version,
                    channel,
                    final_package.name,
                    str(final_package),
                    package_sha,
                    final_package.stat().st_size,
                    notes,
                    utcnow(),
                    actor,
                    final_installer.name,
                    str(final_installer),
                    installer_sha,
                    final_installer.stat().st_size,
                ),
            )
            release_id = int(cur.lastrowid)
        conn.commit()
        return ImportResult(release_id, True, str(final_package), str(final_installer))
    finally:
        conn.close()
