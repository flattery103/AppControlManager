# AppControl Manager 1.0.0-rc.10 Administrator Guide

Use the dashboard to watch endpoint health, approval requests, installation sessions, commands, updates, and background policy work. Begin the release candidate with a small device group and keep deployments paused until the selected endpoints and server backup are verified.

## Daily operations

- Investigate `Offline` devices first, then `Failed` and `Attention` devices.
- `Working` means recent progress is present; do not retry active work merely because policy generation takes several minutes.
- Review policy explanations before approving or revoking software. An explicit active block always wins.
- Use targeted retry for one failed background item. Use retry-all only after a shared worker or service problem is corrected.
- Dismissal hides historical noise; it does not authorize a file or weaken policy.

## Release candidate rollout

Create a deployment in the paused state, assign only the test group, then activate it. Confirm version `1.0.0-rc.10`, valid signatures, service and Rule Worker health, and successful heartbeats before expanding the group. If an endpoint stops reporting, follow `ENDPOINT-SERVICE-RECOVERY.md` before assigning another update.

## Security boundaries

The main service runs as LocalSystem and remains the only policy-install authority. The Rule Worker runs as Local Service and generates policy fragments only. Never create blanket rules for `%TEMP%` or another user-writable directory.
