# AppControl Manager 1.0.0-rc.3 Backup, Restore, and Rollback

Create a database backup before installing the release candidate and before changing a pilot group to Enforcement.

```bash
sudo /root/AppControlManager/server/backup-server.sh /root/appcontrol-manager-before-1.0.0-rc.3.db
```

The backup command refuses to overwrite a file, uses SQLite's online backup API, validates integrity, and restricts permissions.

To restore, stop normal administrative activity and run:

```bash
sudo /root/AppControlManager/server/restore-server.sh /root/appcontrol-manager-before-1.0.0-rc.3.db --confirm
```

The restore script validates the candidate, stops the service, preserves the current database, installs the backup, restarts the service, and checks health. Do not restore a database copied while SQLite WAL files were active unless it was created by the backup script.

For endpoint rollback, use a previously signed and server-registered release through the controlled deployment workflow. Never replace enforced binaries unless their authorization and rollback path have been prepared.
