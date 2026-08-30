# AppControl Manager 1.0.0-rc.7 Acceptance Checklist

## Server and release

- [ ] Database migration completes without data loss.
- [ ] Backup and restore are proven on a nonproduction copy.
- [ ] Server health reports `1.0.0-rc.7`.
- [ ] Main and tag Windows builds pass.
- [ ] The GitHub release is marked prerelease and contains all signed assets.

## Endpoint update and health

- [ ] Automatic update completes from 0.18.3 with rollback protection.
- [ ] Service, tray, and Rule Worker report healthy after reboot.
- [ ] Windows binaries report FileVersion `1.0.0.0` and valid signatures.
- [ ] Paused and resumed group rollout behavior is verified.

## Learning and Enforcement

- [ ] Long-term learning covers normal applications, maintenance, and installations.
- [ ] Expected temporary execution does not create blanket path trust.
- [ ] Known malware and unsigned temporary payloads remain blocked.
- [ ] Policy explanations correctly identify allow, block, scope, and lineage.
- [ ] Per-item retry, retry-all, and dismissal behave as documented.
- [ ] Enforcement survives reboot, application updates, and installer cleanup.

## Production gate

- [ ] Tenant and role isolation tests pass.
- [ ] Restore and endpoint rollback drills pass.
- [ ] No unresolved integrity failure remains.
- [ ] Pilot observation period is complete before promoting `1.0.0`.
