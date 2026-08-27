#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

from release_management import import_agent_release


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a verified AppControl Manager agent release into the server catalog.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--installer", required=True)
    parser.add_argument("--channel", default="stable", choices=("stable", "beta"))
    parser.add_argument("--notes", default="Imported automatically from GitHub Release.")
    parser.add_argument("--db", default=os.getenv("APPCONTROL_DB", os.getenv("APPGUARD_DB", "/opt/appcontrol-manager/appcontrol-manager.db")))
    parser.add_argument("--release-dir", default=os.getenv("APPCONTROL_RELEASE_DIR", "/opt/appcontrol-manager/releases"))
    args = parser.parse_args()

    result = import_agent_release(
        db_path=Path(args.db),
        release_dir=Path(args.release_dir),
        version=args.version,
        package_path=Path(args.package),
        installer_path=Path(args.installer),
        notes=args.notes,
        channel=args.channel,
    )
    state = "imported" if result.imported else "already present"
    print(f"Agent release {args.version} {state} as release #{result.release_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
