# AppControl Manager 1.0 Release Candidate Design

## Goal

Deliver the remaining product, operational, security, and deployment capabilities as one feature-complete `1.0.0-rc.1` release. AppControl Manager 0.18.3 remains the installed baseline during development. The server and test endpoint are updated only after the release candidate passes automated and build verification.

The release candidate must be suitable for an extended Learning Mode soak, a controlled multi-device pilot, and a staged Enforcement test. Defects found during that acceptance cycle are corrected together in `1.0.0-rc.2` only when necessary. The final `1.0.0` contains no new features beyond the accepted release candidate.

## Non-negotiable security boundaries

- `AppControlManager` remains LocalSystem and is the only process permitted to convert, install, remove, merge, or refresh WDAC policies.
- `AppControlManagerRuleWorker` remains Local Service and performs constrained, generation-only ConfigCI work.
- Explicit BLOCK rules retain precedence over approvals and learned authorization.
- Enforcement restoration, update activation, and rollback remain fail-closed.
- No blanket `%TEMP%`, user-writable directory, publisher, or path allow rule is introduced.
- Server-side organization and role checks are enforced in queries and mutations; hiding a control in the UI is never treated as authorization.
- Existing 0.18.3 enrollment, approvals, installed policies, blocks, learning history, installation requests, and audit records remain compatible.

## Delivery approach

Development occurs in one isolated release-candidate branch/worktree and is divided into internal implementation gates. These gates are not separately published releases:

1. Operational data and explanations.
2. Administrator UI and diagnostics.
3. Controlled deployment and update recovery.
4. Temporary-execution classification and learning presentation.
5. Authorization, tenant-isolation, backup, and rollback hardening.
6. Versioning, documentation, packaging, and complete verification.

Each gate receives failing-first regression tests and focused verification. Only the complete result is packaged and tagged.

## 1. Policy explanation and lineage

The server must answer two administrator questions without requiring interpretation of raw logs:

- Why is this application allowed?
- Why was this application blocked or requested?

### Canonical explanation model

Add a server-side policy-lineage projection assembled from existing scoped policies, approval requests and items, approved applications/components, background policies, blocked applications, commands, installation requests, and audit records. Store new linkage identifiers only where the existing tables cannot reconstruct the relationship reliably.

Each explanation contains:

- decision: allowed, blocked, pending, learned, revoked, failed, or unknown;
- identity: file path, SHA-256, publisher, product, version, and rule type when known;
- source: explicit block, manual approval, grouped approval, installation session, learned rule, scoped policy, background expansion, or base policy;
- scope: device, group, organization, or global;
- lineage: originating request/session/policy, approving administrator or policy engine, command, installed WDAC policy ID, and current revocation state;
- timestamps and a concise human-readable explanation;
- bounded diagnostic detail that excludes secrets and raw device keys.

The projection must not claim that a revoked policy made a file blocked when another active policy can still authorize it. Such cases display **Revoked, but may remain allowed by another active policy** until endpoint policy evidence confirms otherwise.

### UI

Application, request, approval, block, and device views gain a consistent **Why?** or **Policy details** action. The result prioritizes a plain-language summary and then shows technical identity and lineage fields.

## 2. Background policy operations

Replace the device page's aggregate-only panel with a drill-down operational view while preserving the compact summary.

### Endpoint telemetry

The heartbeat adds a bounded list of current background work summaries. Each item contains a stable cache-key digest, safe display name, kind, lifecycle state, attempts, elapsed or queued age, rule mode, last error category, and last update time. Full paths are reported only when already authorized for administrative display and are length-bounded.

### Lifecycle states

Normalize background work into:

- `queued`
- `processing`
- `ready`
- `installed`
- `skipped_ephemeral`
- `needs_attention`
- `failed`

Expected ephemeral files do not count as failures. A retryable timeout or unavailable representative becomes `needs_attention` when primary authorization remains intact. `failed` is reserved for work whose failure prevents the intended authorization result or indicates an integrity/security boundary violation.

### Administrator actions

- Retry one failed/attention item.
- Retry all eligible failed/attention work.
- Dismiss a historical, non-security operational record without deleting audit history.
- Inspect attempts, durations, result mode, and sanitized errors.

Retry remains idempotent, retains installed/ready work, and cannot accept administrator-provided paths or worker arguments.

## 3. Endpoint health and diagnostics

Create one device-health projection combining existing and new heartbeat fields:

- main service and Rule Worker status;
- tray presence/status where observable;
- current policy mode and last successful policy refresh;
- background queue health and last successful completion;
- installed agent version and desired version;
- update stage, last successful update, last failure, and rollback state;
- last heartbeat, event-upload success, and command-loop success;
- restart-required or administrator-action-required flags.

Health is displayed as `Healthy`, `Working`, `Attention`, `Failed`, or `Offline`. Long but progressing ConfigCI generation is `Working`, not failed. Thresholds use last-progress timestamps rather than a single wall-clock timeout.

The device page offers a copyable diagnostic summary that contains no enrollment token, device key, session cookie, password material, or signing credential.

## 4. Filtering and operational navigation

Add server-side, organization-scoped filtering to requests, applications, events, audit records, background work, devices, and update history.

Supported filters are limited to fields administrators use operationally:

- organization and group where the principal is authorized;
- device/hostname;
- application/product/publisher text;
- lifecycle status;
- decision or event type;
- date range;
- active versus historical records.

Filters use parameterized SQL, bounded input lengths, deterministic pagination, and stable ordering. URLs retain filter state so administrators can bookmark or share a view with another authorized administrator.

## 5. Controlled agent rollout

Extend the existing `agent_releases`, `agent_deployments`, rollout percentage, and update-history model instead of creating a separate deployment engine.

### Controls

- Target global, organization, group, or selected device scope.
- Start in paused state or activate immediately.
- Set or change rollout percentage.
- Pause future assignments without interrupting an endpoint already activating an update.
- Resume a deployment deterministically; the same device remains inside or outside a percentage cohort.
- Cancel queued, unclaimed updates while preserving completed history.
- Require explicit administrator retry after failed/rolled-back updates or target a newer release.

### Visibility

Show eligible, queued, downloading, staging, activating, completed, failed, rolled back, canceled, and excluded counts. Each endpoint exposes its latest transition and bounded detail. A deployment never loops automatically after a recorded failure.

### Release integrity

Every release continues to require HTTPS download, SHA-256 verification, Authenticode verification, expected signer identity, preauthorization, rollback-protected activation, post-activation health verification, and cleanup.

## 6. Temporary execution and learning noise

Retain the 0.18.x narrow .NET extraction classifier and add an evidence model rather than a broad temporary-path exclusion.

### Classification signals

A temporary executable may be classified as expected ephemeral only when multiple signals support it, including the applicable subset of:

- execution occurred inside an active installation or learning session;
- parent/ancestor process is part of the observed installer chain;
- valid signature and signer continuity with the approved installer or installed product;
- known, structurally validated extraction pattern;
- file is short-lived or already unavailable;
- the durable installed application has usable authorization coverage;
- no explicit block, conflicting signer, or suspicious writable-path persistence signal exists.

Classification changes presentation and background-work disposition; it never grants execution by path. Unknown, unsigned, conflicting, or persistent TEMP executables remain visible and subject to approval/block behavior.

### User experience

Expected ephemeral artifacts are summarized as skipped operational detail and do not nag the user or mark an otherwise successful installation as failed. Administrators can expand the summary to inspect counts and reasons. Security-relevant unknowns remain individual requests.

## 7. Authorization and tenant-isolation hardening

Perform a route-by-route authorization review covering every HTML and API read/mutation.

- Global administrators can act across organizations.
- Organization administrators are confined to their organization.
- Approvers can perform only approval/policy actions allowed by their role and organization.
- Read-only users cannot trigger commands or mutations.
- Device authentication can access only the authenticated device's heartbeat, events, commands, and completion endpoints.
- Object IDs supplied by clients are always resolved and checked against organization scope before use.
- Bulk actions re-check every selected object; mixed-scope requests fail closed.
- Audit entries capture actor, organization, device/object, action, timestamp, and bounded result.

Add negative tests for cross-organization enumeration, direct-object references, filter manipulation, bulk operations, command completion, deployment targeting, and policy lineage.

## 8. Backup, restore, rollback, and recovery

Provide documented and testable administrator procedures:

- consistent SQLite backup while the service is safely coordinated;
- backup integrity verification;
- restoration into a clean server installation;
- validation of users, organizations, devices, policies, approvals, blocks, releases, and audit history after restore;
- server-code rollback with database-schema forward compatibility;
- agent update rollback and manual signed-installer recovery;
- recovery from stopped Rule Worker, interrupted policy generation, interrupted update activation, and unavailable release assets.

Schema migrations remain additive and idempotent. No release-candidate migration may silently delete or reinterpret existing authorization records.

## 9. Versioning and release publication

Use Git tag and GitHub prerelease name `v1.0.0-rc.1`. Windows PE/FileVersion remains numeric `1.0.0.0`; ProductVersion and server display may include `1.0.0-rc.1`.

Update comparison must understand prerelease precedence:

`0.18.3 < 1.0.0-rc.1 < 1.0.0-rc.2 < 1.0.0`

The server must never downgrade a final release to an RC. Release publication marks RC tags as GitHub prereleases and final `v1.0.0` as the latest stable release. The existing fail-closed build, signing, signature-verification, and asset-manifest gates remain mandatory.

## 10. Testing and acceptance

### Automated gates during development

- Complete Python server suite and migration tests.
- Route-level role and tenant-isolation matrix.
- Policy explanation and lineage tests, including overlapping and revoked policies.
- Background lifecycle, item retry, timeout/progress, and ephemeral classification tests.
- Filtering, pagination, and injection-resistance tests.
- Deployment cohort, pause/resume/cancel, retry latch, and prerelease comparison tests.
- .NET Windows behavior tests for worker validation, policy processing, telemetry, and updater behavior.
- Self-contained x64 service, tray, Rule Worker, and installer builds.
- Workflow tests, YAML validation, release-probe tests, asset checksums, signing, and signature verification.
- `git diff --check` and version-surface consistency tests.

### Release-candidate deployment gate

1. Back up and update the server once from 0.18.3 source to 1.0.0-rc.1.
2. Publish the signed prerelease and verify every expected asset.
3. Use a one-device deployment to prove automatic 0.18.3 to 1.0.0-rc.1 update and rollback protection.
4. Confirm endpoint enrollment, policies, approvals, blocks, learning history, and installation requests survive.

### Major acceptance cycle

- Extended normal-use Learning Mode soak.
- Windows, browser, Office, security-agent, and line-of-business updates.
- Application install/uninstall, portable tools, TEMP extraction, reboots, and sign-ins.
- Background work, retry, worker-stop/restart, and representative-file loss scenarios.
- Learning-to-Enforcement transition and repeated application launches.
- Explicit allow, block, unblock, revoke, overlapping-policy, and explanation tests.
- Multi-device staged rollout, pause/resume, failure, rollback, and recovery.
- Cross-role and cross-organization security validation.
- Database backup/restore and clean-server recovery drill.

All release-candidate defects are recorded and corrected without adding new features. A second RC is published only when fixes change deployed server or endpoint behavior materially.

## Documentation deliverables

- Installation and upgrade guide.
- Learning Mode and Enforcement deployment guide.
- Administrator guide for requests, policies, explanations, background work, and rollout.
- Troubleshooting and diagnostic collection guide.
- Backup, restore, rollback, and disaster-recovery guide.
- Release-candidate acceptance checklist and test-results record.

## Out of scope

- Blanket trust or suppression for `%TEMP%` or any user-writable tree.
- Cloud reputation, antivirus replacement, sandbox detonation, or machine-learning malware classification.
- A new Windows service, privileged broker, database engine, message queue, or external telemetry platform.
- Automatic production-wide Enforcement without an administrator-controlled pilot.
- Features added after `1.0.0-rc.1`; only release-blocking corrections proceed to later RCs and `1.0.0`.
