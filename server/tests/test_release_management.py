import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


class ReleaseManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_parse_release_payload_collects_version_notes_and_assets(self):
        from release_management import parse_release_payload

        payload = {
            "tag_name": "v0.15.0",
            "html_url": "https://github.example/releases/v0.15.0",
            "published_at": "2026-08-27T20:00:00Z",
            "body": "Release notes here",
            "assets": [
                {"name": "AppControlManager-0.15.0-source.zip", "url": "https://api.example/source"},
                {"name": "AppControlManager-Agent-0.15.0-win-x64.zip", "url": "https://api.example/agent"},
            ],
        }

        info = parse_release_payload(payload)

        self.assertEqual("0.15.0", info.version)
        self.assertEqual("Release notes here", info.notes)
        self.assertEqual("https://api.example/agent", info.assets["AppControlManager-Agent-0.15.0-win-x64.zip"])
        self.assertEqual("2026-08-27T20:00:00Z", info.published_at)

    def test_verify_sha256_file_accepts_matching_checksum_and_rejects_mismatch(self):
        from release_management import verify_sha256_file

        payload = self.root / "payload.bin"
        payload.write_bytes(b"appcontrol")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        checksum = self.root / "payload.bin.sha256"
        checksum.write_text(f"{digest}  payload.bin\n", encoding="ascii")

        self.assertEqual(digest, verify_sha256_file(payload, checksum))

        checksum.write_text(f"{'0' * 64}  payload.bin\n", encoding="ascii")
        with self.assertRaises(ValueError):
            verify_sha256_file(payload, checksum)

    def _make_package(self, version="0.15.0"):
        package = self.root / f"AppControlManager-Agent-{version}-win-x64.zip"
        manifest = {
            "product": "AppControl Manager Agent",
            "version": version,
            "platform": "win-x64",
            "files": [],
        }
        with zipfile.ZipFile(package, "w") as zf:
            zf.writestr("agent-manifest.json", json.dumps(manifest))
        installer = self.root / f"AppControlManager-Installer-{version}.exe"
        installer.write_bytes(b"MZ-test-installer")
        return package, installer

    def _make_db(self):
        db_path = self.root / "test.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(
            """
            CREATE TABLE agent_releases (
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
                installer_file_name TEXT,
                installer_file_path TEXT,
                installer_sha256 TEXT,
                installer_size_bytes INTEGER,
                deleted_at TEXT,
                deleted_by TEXT,
                UNIQUE(version,channel)
            );
            """
        )
        conn.close()
        return db_path

    def test_import_agent_release_copies_files_and_is_idempotent(self):
        from release_management import import_agent_release

        db_path = self._make_db()
        release_dir = self.root / "releases"
        package, installer = self._make_package()

        first = import_agent_release(
            db_path=db_path,
            release_dir=release_dir,
            version="0.15.0",
            package_path=package,
            installer_path=installer,
            notes="Imported from GitHub",
        )
        second = import_agent_release(
            db_path=db_path,
            release_dir=release_dir,
            version="0.15.0",
            package_path=package,
            installer_path=installer,
            notes="Imported from GitHub",
        )

        self.assertTrue(first.imported)
        self.assertFalse(second.imported)
        self.assertEqual(first.release_id, second.release_id)
        self.assertTrue((release_dir / package.name).is_file())
        self.assertTrue((release_dir / installer.name).is_file())

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT version,channel,active,created_by,sha256,installer_sha256 FROM agent_releases").fetchone()
        count = conn.execute("SELECT COUNT(*) FROM agent_releases").fetchone()[0]
        conn.close()
        self.assertEqual(1, count)
        self.assertEqual(("0.15.0", "stable", 1, "github-updater"), row[:4])
        self.assertEqual(64, len(row[4]))
        self.assertEqual(64, len(row[5]))

    def test_import_agent_release_rejects_manifest_version_mismatch(self):
        from release_management import import_agent_release

        db_path = self._make_db()
        package, installer = self._make_package(version="0.14.9")
        with self.assertRaises(ValueError):
            import_agent_release(
                db_path=db_path,
                release_dir=self.root / "releases",
                version="0.15.0",
                package_path=package,
                installer_path=installer,
                notes="bad",
            )


if __name__ == "__main__":
    unittest.main()
