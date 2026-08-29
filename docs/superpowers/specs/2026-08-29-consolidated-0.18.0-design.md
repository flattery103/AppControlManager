# AppControl Manager 0.18.0 Consolidated Reliability Design

## Goal

Publish one consolidated 0.18.0 release instead of several small endpoint updates. The release repairs GitHub release creation, moves the remaining ConfigCI rule-generation work out of LocalSystem, makes failed background policy work recoverable from the server, and narrowly classifies expected .NET single-file extraction artifacts during learning.

The release must preserve the security boundaries proven in 0.16.5 through 0.17.2:

- `AppControlManager` remains LocalSystem and is the only process that converts, installs, removes, merges, or refreshes WDAC policies.
- `AppControlManagerRuleWorker` remains Local Service and performs generation-only ConfigCI work against a staged file in a constrained job directory.
- Enforcement restoration and explicit BLOCK precedence remain fail-closed.
- No blanket `%TEMP%` trust or exclusion is introduced.

## Scope

### 1. Recoverable GitHub release publication

The release workflow must distinguish an expected missing GitHub Release from a real `gh` failure without allowing Windows PowerShell 5.1 to terminate the step on `gh release view` stderr.

- Probe release existence through `cmd.exe`, redirecting the expected `release not found` output outside PowerShell's native-error stream.
- Capture the probe exit code explicitly.
- Exit code `0` uploads assets with `--clobber` and refreshes the title/latest flag.
- Exit code `1` creates the release and uploads all assets.
- Any other probe result fails with a diagnostic.
- Preserve the existing fail-closed signing and signature-verification gates.

### 2. Complete the Local Service generation boundary

The current worker supports reusable `product` and `hash` allow fragments. Version 0.18.0 adds two fixed generation operations:

- `primary_allow`: generate the foreground allow policy XML for one staged primary file, including the existing ProductName/FilePublisher/Hash fallback behavior.
- `deny_policy`: generate the explicit deny policy XML for one staged file, including the existing product-family and conservative per-file fallback behavior.

The worker contract remains closed and file based:

- The request contains a GUID job ID, an allowlisted operation, and a basename-only staged input filename.
- Outputs are fixed by operation (`fragment.xml` for reusable product/hash fragments and `policy.xml` for primary allow/deny generation).
- The request cannot provide a script path, output path, policy installation command, server credential, device key, or arbitrary argument.
- Local Service returns rule count, selected rule type/mode, elapsed time, and sanitized errors.

Generation and installation remain separate:

1. LocalSystem stages the requested file and submits the constrained worker job.
2. Local Service generates unsigned XML only.
3. LocalSystem validates that the expected XML exists inside the job directory and copies it to the protected policy directory.
4. LocalSystem applies policy name/ID/base-policy metadata where required, converts XML to CIP, installs it with `CiTool`, refreshes policy state, verifies success, and returns the existing API result.

The main service continues serializing foreground and background policy operations. Foreground requests retain priority over queued background work.

### 3. Recoverable background policy work and diagnostics

The existing three-attempt bounded retry remains. Version 0.18.0 adds an explicit administrator recovery path after those attempts are exhausted.

- `BackgroundPolicyStore` exposes pending count, failed count, oldest pending timestamp, and a bounded last-error summary.
- A new `retry_background_policy` endpoint command resets failed rule and bundle attempts to zero and returns them to `queued` without altering ready/installed work.
- The device page shows the last background error and a **Retry Failed Background Work** button only when failed work exists and no other endpoint command is active.
- The retry route enforces existing organization access and approver permissions and records an audit event.
- Heartbeats report the bounded error summary so the server can display diagnostics without reading endpoint files.

Rule-worker job cleanup is conservative:

- Successfully consumed jobs continue to be deleted immediately.
- On worker startup, completed failed jobs and abandoned unpublished jobs older than seven days are removed.
- A job with a recent request and no result is never deleted as stale.
- Cleanup never touches the canonical rule-fragment cache or installed policy files.

### 4. Narrow .NET extraction classification

Add one shared learned-path classifier for the documented default .NET single-file extraction structure:

`<recognized temp root>\.net\<application>\<bundle-id>\...`

Recognition requirements:

- Case-insensitive `.net` directory name.
- A recognized Windows user or system temporary root.
- Non-empty application and bundle-ID directory segments plus at least one extracted child file.
- Canonicalized path must remain beneath that temporary root.

Recognized extraction children are treated as expected ephemeral learning artifacts, not authorization candidates. They do not increment the unresolved/unpreparable count and therefore do not by themselves make an otherwise valid Enable Enforcement or Installation Mode finalization fail or warn.

Security constraints:

- Do not ignore all files beneath `%TEMP%`.
- Do not classify NSIS `nsh*.tmp`, MSI caches, arbitrary temporary directories, or a file merely because its name/product contains `.NET`.
- Do not create an allow rule for the extraction directory.
- If a learning/install session contains only ignored extraction children and produces no usable authorization rule, finalization still fails safely with a clear no-usable-rule result.

Diagnostics record observed, candidate, ignored-ephemeral, skipped/unverifiable, and installed counts separately. Existing API status values remain compatible.

## Data and API changes

The `devices` table adds nullable `background_policy_error` and `background_policy_oldest_at` columns through the existing non-destructive `ensure_column` migration style.

The heartbeat request adds `background_policy_error` and `background_policy_oldest_at`. Older agents omit them; newer servers retain compatibility through optional fields.

The new command type is `retry_background_policy`. Its payload records `requested_by`; it accepts no paths, policy IDs, or arbitrary retry parameters.

No enrollment, policy, approval, installation-request, learning-history, or audit tables are deleted or rewritten.

## User interface

The device's existing **Background Policy Work** panel gains:

- bounded last-error text when available;
- the oldest pending-work timestamp when available;
- the existing pending and failed counts;
- **Retry Failed Background Work** when the viewer can approve, failures exist, and the device command queue is free.

No new top-level navigation item is added in 0.18.0.

## Failure and rollback behavior

- Worker generation failure does not grant authorization or install a partial policy.
- Main-service post-processing/install failure reports the existing approval/block failure and preserves Enforcement.
- Background retry is idempotent and never resets installed work.
- A failed managed update must retain the 0.17.1+ complete-backup rollback behavior.
- The signed 0.18.0 installer remains the manual recovery fallback if the automatic 0.17.2 to 0.18.0 test fails.
- AppControl Manager 0.17.2 becomes the current functional rollback baseline; 0.16.2 remains the older Path B architectural reference.

## Version and documentation

Advance all server, agent, tray, installer, build, upgrade-script, workflow default, release-note, and version-test surfaces to `0.18.0`.

Add `0.18.0-FEATURES.txt` and update the README with the consolidated scope and upgrade expectations.

## Verification requirements

### Automated

- Add failing-first regression tests for the Windows PowerShell release probe.
- Add worker-contract tests for the two new allowlisted operations, fixed outputs, and absence of installation commands in the Local Service path.
- Add behavior tests proving LocalSystem performs XML post-processing/conversion/installation after worker generation.
- Add retry-store tests proving only failed rules/bundles are reset and installed/ready work is preserved.
- Add server tests for heartbeat error storage, tenant authorization, command-busy handling, audit recording, and retry-button visibility.
- Add .NET classifier tests for valid user/system extraction paths, path-canonicalization escapes, insufficient segments, NSIS/MSI paths, and arbitrary `%TEMP%` content.
- Add finalization tests proving expected .NET children do not cause warnings when usable rules exist and still cannot produce a successful zero-rule finalization.
- Run the complete Python server suite, `git diff --check`, workflow/YAML validation, .NET behavior tests, and self-contained Windows x64 service/tray/installer publishes.

### Runtime acceptance

1. Install the server update and confirm the matching signed 0.18.0 agent imports automatically.
2. Use the dashboard updater for the test endpoint's 0.17.2 to 0.18.0 transition.
3. Confirm both services are Automatic/Running, both executables are 0.18.0 with valid signatures, cleanup is complete, and the endpoint remains enrolled and Online.
4. Approve a harmless application and confirm foreground authorization completes through the worker and remains effective after Enforcement.
5. Create and revoke a harmless explicit block and confirm deny generation/removal works.
6. Exercise Installation Mode with a .NET single-file application if available; confirm extracted `.net` children are ignored narrowly and the installed host application runs after Enforcement returns.
7. Force one disposable background item into failed state, use the server retry action, and confirm it returns to queued/processing without disturbing installed rules.

## Out of scope

- Policy-source explanations, approval/revocation lineage, broad request filtering, rollout pause controls, and multi-device deployment UX remain planned for 0.19.0.
- The deep tenant/authorization audit and production-readiness gate remain planned for 1.0.0.
- No general temporary-directory allow/exclusion rules.
- No new executable, Windows service, or signing artifact.
