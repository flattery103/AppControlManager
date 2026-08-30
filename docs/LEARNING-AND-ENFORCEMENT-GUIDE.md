# AppControl Manager 1.0.0-rc.4 Learning and Enforcement Guide

Run learning long enough to cover normal sign-in, maintenance, updates, line-of-business applications, and representative installations. Learning observations are evidence, not automatic permanent trust.

## Temporary execution

Temporary files may be legitimate or malicious. The release candidate labels a file as expected ephemeral only during an active installation session when multiple signals agree, including a recognized temporary location, valid publisher evidence, installer ancestry or pattern evidence, and durable application coverage. Classification alone never grants authorization.

## Before Enforcement

1. Confirm no endpoint is Offline or Failed.
2. Resolve or deliberately dismiss every `needs_attention` background item.
3. Review explicit blocks, scoped approvals, and policy explanations for critical applications.
4. Back up the server database.
5. Enable Enforcement on the test group only.

Test application launch, update, repair, uninstall, reboot, user sign-in, and temporary installer behavior. Unexpected files must remain blocked and must not inherit trust from their directory.
