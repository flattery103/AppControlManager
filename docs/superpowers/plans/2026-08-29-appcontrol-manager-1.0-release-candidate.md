# AppControl Manager 1.0 Release Candidate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and package the complete AppControl Manager `1.0.0-rc.1` feature set on the 0.18.3 baseline without publishing intermediate releases.

**Architecture:** Extend the existing FastAPI/SQLite server, heartbeat contract, LocalSystem agent, Local Service Rule Worker, and signed updater. Add operational projections and bounded telemetry while preserving the existing WDAC privilege boundary. Implement in internal test gates and publish only after the combined server, Windows, security, migration, workflow, and packaging gates pass.

**Tech Stack:** Python 3/FastAPI/SQLite/unittest; C#/.NET 8 worker services and WinForms tray; PowerShell 5.1/7; ConfigCI/WDAC; GitHub Actions; Azure Artifact Signing.

**Spec:** `docs/superpowers/specs/2026-08-29-appcontrol-manager-1.0-release-candidate-design.md`

## Global Constraints

- `AppControlManager` remains LocalSystem and is the only WDAC policy installation authority.
- `AppControlManagerRuleWorker` remains Local Service and generation-only.
- Explicit BLOCK precedence and fail-closed Enforcement restoration remain unchanged.
- No blanket `%TEMP%`, user-writable path, or publisher trust is permitted.
- All server reads and mutations enforce role and organization scope in backend code.
- Migrations are additive and idempotent; existing 0.18.3 state remains compatible.
- Windows `FileVersion` is `1.0.0.0`; display/product prerelease version is `1.0.0-rc.1`.
- No intermediate Git tag, GitHub Release, server deployment, or endpoint update is created.

---

### Task 1: Operational telemetry contract and migrations

**Files:**
- Modify: `server/app.py`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Modify: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Create: `server/tests/test_100rc_operational_telemetry.py`
- Modify: `windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs`
- Create: `windows-agent/tests/AppGuard.Core.BehaviorTests/OperationalTelemetryBehavior.cs`

**Interfaces:**
- Produces: `BackgroundWorkSummaryIn` on the server and `BackgroundWorkSummary` in C# with `key_digest`, `display_name`, `kind`, `status`, `attempts`, `age_seconds`, `elapsed_seconds`, `rule_mode`, `error_category`, and `updated_at`.
- Produces: heartbeat fields `service_status`, `rule_worker_status`, `tray_status`, `last_policy_refresh_at`, `last_background_success_at`, `last_event_upload_at`, and `last_command_poll_at`.
- Consumes: existing `BackgroundPolicyStore.GetStatus()` and heartbeat authentication.

- [ ] **Step 1: Write failing server migration and heartbeat tests**

```python
def test_heartbeat_persists_bounded_operational_health(self):
    payload = {
        "hostname": "RC-ENDPOINT",
        "background_work": [{
            "key_digest": "a" * 64,
            "display_name": "Example Product",
            "kind": "product",
            "status": "processing",
            "attempts": 1,
            "age_seconds": 42,
            "elapsed_seconds": 15,
            "rule_mode": "product",
            "error_category": None,
            "updated_at": "2026-08-29T21:00:00+00:00",
        }],
        "service_status": "running",
        "rule_worker_status": "running",
    }
    response = self.client.post("/api/heartbeat", json=payload, headers=self.agent_headers)
    self.assertEqual(response.status_code, 200)
```

- [ ] **Step 2: Run the new server test and verify contract fields are rejected or absent**

Run: `.venv/bin/python -m unittest server.tests.test_100rc_operational_telemetry -q`

Expected: FAIL because the heartbeat model/schema does not yet persist detailed operational telemetry.

- [ ] **Step 3: Write failing Windows serialization and bounded-list tests**

```csharp
var summaries = store.GetWorkSummaries(maxItems: 25);
Require(summaries.Count <= 25, "Background work telemetry must be bounded.");
Require(summaries.All(x => x.KeyDigest.Length == 64), "Telemetry must expose a digest, not a raw cache key.");
```

- [ ] **Step 4: Implement additive columns, JSON storage, Pydantic validation, and C# models**

Add nullable device health columns with `ensure_column`. Store the bounded background list as JSON in `devices.background_work_json`; reject more than 50 items, invalid lifecycle states, digests other than 64 lowercase hex characters, display names over 256 characters, and timestamps over 80 characters. Limit endpoint emission to 25 most-recent non-installed items.

- [ ] **Step 5: Emit progress timestamps from the existing service loops**

Update successful heartbeat/event/command/policy paths in `AgentWorker` and `BackgroundPolicyStore` so each timestamp records successful progress, not merely loop entry.

- [ ] **Step 6: Run focused and complete tests**

Run:

```bash
.venv/bin/python -m unittest server.tests.test_100rc_operational_telemetry -q
.venv/bin/python -m unittest discover -s server/tests -q
dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release
```

Expected: all tests pass.

- [ ] **Step 7: Commit the telemetry gate**

```bash
git add server/app.py server/tests/test_100rc_operational_telemetry.py windows-agent/src/AppGuard.Core/Models.cs windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs windows-agent/src/AppGuard.Service/AgentWorker.cs windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs windows-agent/tests/AppGuard.Core.BehaviorTests/OperationalTelemetryBehavior.cs
git commit -m "Add release candidate operational telemetry"
```

---

### Task 2: Background work lifecycle and targeted recovery

**Files:**
- Modify: `server/app.py`
- Modify: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs`
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Create: `server/tests/test_100rc_background_operations.py`
- Create: `windows-agent/tests/AppGuard.Core.BehaviorTests/BackgroundLifecycleBehavior.cs`
- Modify: `windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs`

**Interfaces:**
- Produces: lifecycle states `queued`, `processing`, `ready`, `installed`, `skipped_ephemeral`, `needs_attention`, and `failed`.
- Produces: commands `retry_background_policy_item` with `{key_digest, requested_by}` and `dismiss_background_policy_item` with `{key_digest, requested_by}`.
- Consumes: Task 1 background-work telemetry.

- [ ] **Step 1: Write failing lifecycle classification tests**

```csharp
Require(BackgroundLifecycle.Classify(primaryAuthorizationIntact: true, errorCategory: "timeout") == "needs_attention",
    "A retryable auxiliary timeout must need attention, not report a security failure.");
Require(BackgroundLifecycle.Classify(primaryAuthorizationIntact: false, errorCategory: "integrity") == "failed",
    "Integrity failures must remain failed.");
```

- [ ] **Step 2: Write failing server tests for single-item retry, retry-all, and dismissal**

Assert organization access, approver role, command-busy handling, 64-hex digest validation, audit creation, and absence of administrator-controlled paths or worker arguments.

- [ ] **Step 3: Run focused tests and verify failures**

Run:

```bash
.venv/bin/python -m unittest server.tests.test_100rc_background_operations -q
dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release
```

- [ ] **Step 4: Implement lifecycle normalization and progress-aware timeout handling**

Treat work as progressing while its worker job has a newer progress timestamp. Map missing disposable representatives and bounded auxiliary timeouts to `needs_attention` when primary authorization remains installed. Reserve `failed` for integrity mismatch, invalid generated policy, installation-preventing failure, or exhausted work without primary coverage.

- [ ] **Step 5: Implement constrained targeted commands and UI routes**

Add the two command types to server and agent allowlists. Resolve a digest only against the endpoint's local store. Retry resets only the matching eligible record; dismissal hides only historical attention/failure presentation and preserves an audit entry.

- [ ] **Step 6: Run focused and regression suites**

Run the commands from Step 3, then `.venv/bin/python -m unittest discover -s server/tests -q`.

- [ ] **Step 7: Commit the background-operations gate**

```bash
git add server/app.py server/tests/test_100rc_background_operations.py windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs windows-agent/src/AppGuard.Service/AgentWorker.cs windows-agent/tests/AppGuard.Core.BehaviorTests/BackgroundLifecycleBehavior.cs windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs
git commit -m "Add detailed background policy operations"
```

---

### Task 3: Policy explanation and lineage

**Files:**
- Modify: `server/app.py`
- Create: `server/tests/test_100rc_policy_explanations.py`

**Interfaces:**
- Produces: `build_policy_explanation(conn, principal, *, device_id, file_path=None, sha256=None, request_id=None, application_id=None, block_id=None) -> dict`.
- Produces: `/policy-explanation` HTML route and `/api/policy-explanation` JSON route.
- Consumes: existing scoped policies, approvals/components, background policies, blocks, commands, installation requests, and audit records.

- [ ] **Step 1: Write failing explanation tests**

Cover manual approval, grouped approval, installation session, scoped auto-approval, background expansion, explicit block, revoked approval with overlapping active authorization, unknown identity, and cross-organization denial.

```python
explanation = app_module.build_policy_explanation(conn, principal, device_id="d1", sha256="ab" * 32)
self.assertEqual(explanation["decision"], "allowed")
self.assertEqual(explanation["source"], "manual_approval")
self.assertEqual(explanation["scope"], "device")
```

- [ ] **Step 2: Run the focused test and verify missing projection failure**

Run: `.venv/bin/python -m unittest server.tests.test_100rc_policy_explanations -q`

- [ ] **Step 3: Implement the deterministic projection**

Resolve explicit active blocks first, then active scoped policies by existing specificity order, then installed approvals/background policies, then pending/history. Include IDs and timestamps required for lineage but never expose credentials or unrestricted filesystem content.

- [ ] **Step 4: Add plain-language HTML and technical detail sections**

Use existing layout helpers and organization checks. Display the overlapping-policy warning whenever a revoked record coexists with another potential authorization source.

- [ ] **Step 5: Run focused and complete server tests**

Run Step 2 and `.venv/bin/python -m unittest discover -s server/tests -q`.

- [ ] **Step 6: Commit the explanation gate**

```bash
git add server/app.py server/tests/test_100rc_policy_explanations.py
git commit -m "Explain policy decisions and lineage"
```

---

### Task 4: Operational filtering and device health UI

**Files:**
- Modify: `server/app.py`
- Create: `server/tests/test_100rc_filters_and_health.py`

**Interfaces:**
- Produces: `parse_operational_filters(params, principal) -> OperationalFilters` with bounded query, status, date, organization, group, and device fields.
- Produces: `classify_device_health(row, now) -> tuple[str, list[str]]`.
- Consumes: Tasks 1-3 telemetry, lifecycle, and explanations.

- [ ] **Step 1: Write failing filter authorization and pagination tests**

Test parameterized special characters, 256-character query limit, invalid dates, stable `id DESC` pagination, organization confinement, forbidden organization IDs, and retained query strings in next/previous links.

- [ ] **Step 2: Write failing health classification tests**

```python
self.assertEqual(classify(online=True, worker="running", progress_recent=True), "Healthy")
self.assertEqual(classify(online=True, worker="running", background="processing", progress_recent=True), "Working")
self.assertEqual(classify(online=True, worker="stopped"), "Attention")
self.assertEqual(classify(online=False), "Offline")
```

- [ ] **Step 3: Run the focused tests and verify failures**

Run: `.venv/bin/python -m unittest server.tests.test_100rc_filters_and_health -q`

- [ ] **Step 4: Implement shared bounded filter parsing and parameterized query clauses**

Apply filters to devices, requests, applications, events, audit log, background work, and update history. Preserve the existing principal organization clause in every query.

- [ ] **Step 5: Implement health summary, detailed diagnostics, and copyable safe report**

Render `Healthy`, `Working`, `Attention`, `Failed`, or `Offline` with reasons. Include only documented safe fields and exclude cookies, tokens, keys, password material, and signing configuration.

- [ ] **Step 6: Run focused and complete tests**

Run Step 3 and `.venv/bin/python -m unittest discover -s server/tests -q`.

- [ ] **Step 7: Commit the operations UI gate**

```bash
git add server/app.py server/tests/test_100rc_filters_and_health.py
git commit -m "Add operational filters and endpoint health"
```

---

### Task 5: Controlled rollout and prerelease version semantics

**Files:**
- Modify: `server/app.py`
- Modify: `windows-agent/src/AppGuard.Service/AgentUpdater.cs`
- Modify: `.github/workflows/build-windows.yml`
- Modify: `.github/workflows/release.yml`
- Create: `server/tests/test_100rc_rollouts.py`
- Create: `server/tests/test_100rc_versions.py`
- Create: `.github/tests/Test-Prerelease-Publishing.ps1`
- Create: `windows-agent/tests/AppGuard.Core.BehaviorTests/PrereleaseUpdateBehavior.cs`
- Modify: `windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs`

**Interfaces:**
- Produces: `ReleaseVersion.parse(value)` on the server with SemVer precedence and a C# equivalent used by `AgentUpdater`.
- Produces: deployment states `paused` and `active`, plus scoped device-selection support.
- Consumes: existing releases, deployments, deterministic percentage cohorts, update history, retry latch, and rollback flow.

- [ ] **Step 1: Write failing version-precedence tests**

Assert exactly:

```text
0.18.3 < 1.0.0-rc.1 < 1.0.0-rc.2 < 1.0.0
```

Also assert that `1.0.0` never targets `1.0.0-rc.2` and Windows PE versions remain numeric.

- [ ] **Step 2: Write failing deployment tests**

Cover paused creation, activation, deterministic cohorts, percentage changes, global/organization/group/device targeting, unauthorized scope, canceling only unclaimed commands, failure retry latch, and newer-release recovery.

- [ ] **Step 3: Run focused Python, C#, and PowerShell tests and verify failures**

```bash
.venv/bin/python -m unittest server.tests.test_100rc_rollouts server.tests.test_100rc_versions -q
dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release
pwsh -NoProfile -File .github/tests/Test-Prerelease-Publishing.ps1
```

- [ ] **Step 4: Implement consistent SemVer prerelease comparison**

Accept numeric `major.minor.patch` and `major.minor.patch-rc.N`; reject other labels. Keep agent assembly/file version numeric and transmit the display version separately.

- [ ] **Step 5: Extend deployment controls and visibility**

Reuse existing tables with additive `status` and explicit selected-device linkage. Pausing prevents new command assignment but does not terminate claimed activation. Cancel only queued/unclaimed commands and record audit/update-history results.

- [ ] **Step 6: Mark RC GitHub releases as prereleases**

Derive prerelease status from the validated tag. Preserve all signing, checksum, manifest, and upload gates.

- [ ] **Step 7: Run focused suites, existing release tests, and full server tests**

Run Step 3 plus `.venv/bin/python -m unittest discover -s server/tests -q` and existing `.github/tests/Test-Publish-GitHubRelease.ps1`.

- [ ] **Step 8: Commit the rollout/version gate**

```bash
git add server/app.py server/tests/test_100rc_rollouts.py server/tests/test_100rc_versions.py windows-agent/src/AppGuard.Service/AgentUpdater.cs windows-agent/tests/AppGuard.Core.BehaviorTests/PrereleaseUpdateBehavior.cs windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs .github/workflows/build-windows.yml .github/workflows/release.yml .github/tests/Test-Prerelease-Publishing.ps1
git commit -m "Add controlled prerelease agent rollouts"
```

---

### Task 6: Evidence-based temporary execution classification

**Files:**
- Modify: `windows-agent/src/AppGuard.Service/LearningEventWatcher.cs`
- Modify: `windows-agent/src/AppGuard.Service/LearningFileCache.cs`
- Modify: `windows-agent/src/AppGuard.Service/EventCollector.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Create: `windows-agent/src/AppGuard.Service/EphemeralExecutionClassifier.cs`
- Create: `windows-agent/tests/AppGuard.Core.BehaviorTests/EphemeralExecutionBehavior.cs`
- Modify: `windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs`
- Create: `server/tests/test_100rc_ephemeral_presentation.py`
- Modify: `server/app.py`

**Interfaces:**
- Produces: `EphemeralExecutionClassifier.Classify(EphemeralEvidence evidence) -> EphemeralDisposition`.
- Produces: dispositions `unknown`, `expected_ephemeral`, and `security_relevant`; no disposition grants authorization.
- Consumes: active session identity, installer ancestry when observable, signature/signer continuity, validated path pattern, lifetime/availability, durable rule coverage, and block conflict.

- [ ] **Step 1: Write failing conservative classifier tests**

Cover valid .NET extraction, signed same-publisher installer child with session ancestry and durable coverage, unsigned TEMP executable, mismatched signer, persistent TEMP executable, no active session, explicit block, path traversal, unavailable file with insufficient evidence, and unknown ancestry.

```csharp
Require(classifier.Classify(unsignedTemp).Disposition == "security_relevant",
    "Unsigned TEMP execution must remain visible.");
Require(classifier.Classify(samePublisherInstallerChild).Disposition == "expected_ephemeral",
    "Multi-signal installer extraction may be summarized.");
```

- [ ] **Step 2: Run behavior tests and verify failures**

Run: `dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release`

- [ ] **Step 3: Implement pure evidence classification**

Require an active session plus at least two corroborating non-path signals for generic installer children. An explicit block, invalid signature, signer conflict, canonicalization failure, persistence indicator, or absence of durable coverage prevents `expected_ephemeral`.

- [ ] **Step 4: Integrate classification without path authorization**

Record classification reason/count, set background state `skipped_ephemeral`, and retain security-relevant unknowns as individual requests. Never generate an allow rule from classification alone.

- [ ] **Step 5: Add server presentation tests and implementation**

Render expected ephemeral counts as expandable operational detail. Do not increment failed/warning totals solely for these items. Preserve individual security-relevant requests.

- [ ] **Step 6: Run complete Python and Windows behavior suites**

```bash
.venv/bin/python -m unittest discover -s server/tests -q
dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release
```

- [ ] **Step 7: Commit the learning-noise gate**

```bash
git add server/app.py server/tests/test_100rc_ephemeral_presentation.py windows-agent/src/AppGuard.Core/Models.cs windows-agent/src/AppGuard.Service/EphemeralExecutionClassifier.cs windows-agent/src/AppGuard.Service/LearningEventWatcher.cs windows-agent/src/AppGuard.Service/LearningFileCache.cs windows-agent/src/AppGuard.Service/EventCollector.cs windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs windows-agent/tests/AppGuard.Core.BehaviorTests/EphemeralExecutionBehavior.cs windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs
git commit -m "Classify temporary execution with bounded evidence"
```

---

### Task 7: Authorization matrix and recovery tooling

**Files:**
- Modify: `server/app.py`
- Create: `server/tests/test_100rc_authorization_matrix.py`
- Create: `server/backup-server.sh`
- Create: `server/restore-server.sh`
- Create: `server/tests/test_100rc_backup_restore.py`
- Modify: `server/upgrade-server.sh`

**Interfaces:**
- Produces: route/mutation authorization matrix exercised by tests.
- Produces: `backup-server.sh OUTPUT_PATH` and `restore-server.sh BACKUP_PATH --confirm` with integrity checks and service coordination.
- Consumes: existing Principal roles, organization filters, audit helper, SQLite database path from `/etc/appcontrol-manager.env`, and systemd service.

- [ ] **Step 1: Inventory every HTML/API method and encode the expected role/scope matrix**

The test enumerates registered routes and fails when an administrative mutation is absent from the explicit matrix. Include direct-object, bulk, filters, explanations, deployments, commands, and completion endpoints.

- [ ] **Step 2: Write failing negative authorization tests**

Test global admin, organization admin, approver, read-only, unauthenticated browser, correct device credential, wrong device credential, mixed-organization bulk IDs, and forged object IDs.

- [ ] **Step 3: Run the authorization suite and capture every failure**

Run: `.venv/bin/python -m unittest server.tests.test_100rc_authorization_matrix -q`

- [ ] **Step 4: Correct backend authorization gaps and audit mutations**

Resolve each object before mutation, call `require_org_access`, reject mixed scopes atomically, and audit both accepted high-risk actions and validation rejections without recording secrets.

- [ ] **Step 5: Write failing backup/restore integration tests**

Create a populated temporary database, invoke backup logic, run `PRAGMA integrity_check`, restore to a clean path, and compare counts/identities for organizations, users, devices, scoped policies, approvals, blocks, releases, update history, and audit records.

- [ ] **Step 6: Implement safe backup and explicit restore scripts**

Use SQLite's online backup operation or coordinated service stop; write to a new explicit file; validate integrity before success. Restore requires `--confirm`, preserves the displaced database as a timestamped recovery copy, validates the candidate before replacement, preserves ownership/mode, restarts the service, and checks `/health`.

- [ ] **Step 7: Run authorization, backup/restore, full server, and shell syntax tests**

```bash
.venv/bin/python -m unittest server.tests.test_100rc_authorization_matrix server.tests.test_100rc_backup_restore -q
.venv/bin/python -m unittest discover -s server/tests -q
bash -n server/backup-server.sh server/restore-server.sh server/upgrade-server.sh
```

- [ ] **Step 8: Commit the security/recovery gate**

```bash
git add server/app.py server/tests/test_100rc_authorization_matrix.py server/tests/test_100rc_backup_restore.py server/backup-server.sh server/restore-server.sh server/upgrade-server.sh
git commit -m "Harden authorization and server recovery"
```

---

### Task 8: Version surfaces, documentation, and final package gates

**Files:**
- Create: `1.0.0-RC1-FEATURES.txt`
- Modify: `README.md`
- Modify: `server/app.py`
- Modify: `server/upgrade-server.sh`
- Modify: `.github/workflows/build-windows.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `windows-agent/Build.ps1`
- Modify: `windows-agent/Install-Agent.ps1`
- Modify: `windows-agent/Upgrade-Agent.ps1`
- Modify: `windows-agent/src/AppGuard.Core/AppGuard.Core.csproj`
- Modify: `windows-agent/src/AppGuard.Service/AppGuard.Service.csproj`
- Modify: `windows-agent/src/AppGuard.Tray/AppGuard.Tray.csproj`
- Modify: `windows-agent/src/AppControlManager.Installer/AppControlManager.Installer.csproj`
- Modify: `windows-agent/src/AppControlManager.Installer/Program.cs`
- Modify: `server/tests/test_version_surfaces.py`
- Create: `docs/ADMINISTRATOR-GUIDE.md`
- Create: `docs/LEARNING-AND-ENFORCEMENT-GUIDE.md`
- Create: `docs/BACKUP-RESTORE-ROLLBACK.md`
- Create: `docs/RC-ACCEPTANCE-CHECKLIST.md`

**Interfaces:**
- Produces: server/product display version `1.0.0-rc.1`, numeric Windows file version `1.0.0.0`, and tag `v1.0.0-rc.1`.
- Consumes: all previous tasks and the existing signed build/release workflows.

- [ ] **Step 1: Update version-surface tests first**

Assert every required server, script, workflow default, project, installer, README, and release-note surface. Assert PE version strings remain numeric and display/tag surfaces retain `-rc.1`.

- [ ] **Step 2: Run version tests and verify they fail on 0.18.3**

Run: `.venv/bin/python -m unittest server.tests.test_version_surfaces -q`

- [ ] **Step 3: Update all version surfaces and release notes**

Use `1.0.0.0` only where Windows/MSBuild requires a numeric version. Use `1.0.0-rc.1` for server health/UI, ProductVersion/informational version, documentation, artifact names, and release metadata.

- [ ] **Step 4: Write operational documentation**

Document installation/upgrade, Learning Mode, Enforcement transition, explanation pages, background work, rollout controls, diagnostic collection, backup/restore, rollback, manual signed-installer recovery, and the exact RC acceptance sequence.

- [ ] **Step 5: Run complete source verification**

```bash
.venv/bin/python -m unittest discover -s server/tests -q
git diff --check
bash -n server/install-server.sh server/upgrade-server.sh server/backup-server.sh server/restore-server.sh
dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release
pwsh -NoProfile -File .github/tests/Test-InstalledPolicyValidation.ps1
pwsh -NoProfile -File .github/tests/Test-Publish-GitHubRelease.ps1
pwsh -NoProfile -File .github/tests/Test-Prerelease-Publishing.ps1
```

Expected: every test exits zero.

- [ ] **Step 6: Produce unsigned local Windows builds for compile verification**

Run the existing `windows-agent/Build.ps1` without publication credentials, producing self-contained x64 service, tray, Rule Worker, and installer outputs. Verify each expected executable exists and reports numeric file version `1.0.0.0`.

- [ ] **Step 7: Inspect the complete diff and run secret/credential scan**

Review `git diff --stat`, `git diff`, and tracked additions. Search for enrollment tokens, device keys, cookies, private keys, Azure signing credentials, and local absolute development paths. Any discovered secret blocks packaging.

- [ ] **Step 8: Commit the release-candidate surfaces**

```bash
git add 1.0.0-RC1-FEATURES.txt README.md server/app.py server/upgrade-server.sh .github/workflows/build-windows.yml .github/workflows/release.yml windows-agent docs server/tests/test_version_surfaces.py
git commit -m "Prepare AppControl Manager 1.0 release candidate"
```

- [ ] **Step 9: Create the complete source ZIP without publishing**

Archive tracked source from the verified release-candidate commit into `AppControlManager-1.0.0-rc.1-source.zip`, list and test the archive, and record its SHA-256. Do not push, tag, create a GitHub Release, update the server, or update an endpoint during this step.

---

### Task 9: Human-controlled release-candidate deployment and acceptance

**Files:**
- Update after testing: `docs/RC-ACCEPTANCE-CHECKLIST.md`

**Interfaces:**
- Consumes: verified source ZIP and signed GitHub assets.
- Produces: recorded RC acceptance evidence and the decision to fix in RC2 or promote to `1.0.0`.

- [ ] **Step 1: Provide one complete server update, commit, push, and tag command sequence**

Include backup, source replacement while preserving `.git`, dependency update, tests, live server update, health check, explicit `git add`, commit, push to `main`, annotated `v1.0.0-rc.1` tag, and tag push.

- [ ] **Step 2: Verify all expected GitHub Actions and signed release assets**

Require the main build, tag build, and prerelease publication runs. Verify installer/service/tray/worker signatures, asset checksums, and prerelease status before assigning an endpoint update.

- [ ] **Step 3: Deploy to one 0.18.3 endpoint**

Use a selected-device deployment. Verify download, SHA-256, signer, preauthorization, activation, service health, version, cleanup, and rollback status.

- [ ] **Step 4: Execute the major acceptance checklist**

Complete Learning Mode soak, TEMP/installer behavior, background operations, policy explanations, approvals/blocks/revocations, Enforcement transition, multi-device rollout, authorization matrix, backup/restore, and rollback drills.

- [ ] **Step 5: Freeze scope and decide disposition**

Release-blocking defects go into `1.0.0-rc.2`; no features are added. If no release-blocking defects remain, prepare final `1.0.0` using the same tested code plus version/release-note changes only.
