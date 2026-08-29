# AppControl Manager 0.18.0 Consolidated Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver one signed-ready 0.18.0 source package that repairs automatic GitHub Release creation, completes the Local Service generation boundary, makes failed background policy work recoverable, and narrowly ignores expected .NET single-file extraction children during learning.

**Architecture:** Keep policy generation and installation separated by the existing file-based Rule Worker boundary. The Local Service worker accepts only four fixed operations and emits unsigned XML; LocalSystem validates, post-processes, converts, installs, refreshes, and verifies policies. Background retry state remains endpoint-local and is summarized through heartbeats for the tenant-scoped server UI.

**Tech Stack:** C#/.NET 10 Windows services and behavior-test executable, Windows PowerShell 5.1 ConfigCI helpers, FastAPI/Pydantic/SQLite server, Python `unittest`, GitHub Actions YAML.

**Spec:** `docs/superpowers/specs/2026-08-29-consolidated-0.18.0-design.md`

## Global Constraints

- `AppControlManager` remains LocalSystem and is the only process that converts, installs, removes, merges, or refreshes WDAC policies.
- `AppControlManagerRuleWorker` remains Local Service and performs generation-only ConfigCI work.
- Worker requests accept only a GUID job ID, one of `product`, `hash`, `primary_allow`, or `deny_policy`, and a basename-only input filename.
- Worker outputs are fixed: `fragment.xml` for `product`/`hash`, and `policy.xml` for `primary_allow`/`deny_policy`.
- Enforcement restoration and explicit BLOCK precedence remain fail-closed.
- Never trust, allow, or ignore all of `%TEMP%`; only the documented `.net\<application>\<bundle-id>\<child>` shape under recognized Windows temp roots is ephemeral.
- Failed background retries reset only failed rules/bundles; ready and installed state is immutable.
- Server schema changes use non-destructive `ensure_column` migrations and remain compatible with older agents.
- No GitHub push, tag, release, or server deployment is performed from this worktree.

---

### Task 1: Behavior-first release publication probe

**Files:**
- Create: `.github/scripts/Publish-GitHubRelease.ps1`
- Create: `.github/tests/Test-Publish-GitHubRelease.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `server/tests/test_release_workflow.py`

**Interfaces:**
- Consumes: `GH_TOKEN`, a tag, release title, and the six files under `release/`.
- Produces: exit-code-aware GitHub Release create/update behavior safe under Windows PowerShell 5.1.

- [ ] **Step 1: Write the failing behavior test**

Create a fake `gh.cmd` that returns `1` for `release view`, records `release create`, and returns `2` in a second case. Invoke `Publish-GitHubRelease.ps1` and assert that exit `1` creates a release while exit `2` throws without calling create.

```powershell
& $publisher -Tag 'v0.18.0' -Version '0.18.0' -AssetsDirectory $assets -GhCommand $fakeGh
if (-not (Select-String -LiteralPath $calls -SimpleMatch 'release create v0.18.0')) { throw 'Missing release was not created.' }
```

- [ ] **Step 2: Run the Windows probe test and confirm RED**

Run: `powershell -NoProfile -File .github/tests/Test-Publish-GitHubRelease.ps1`

Expected: FAIL because `.github/scripts/Publish-GitHubRelease.ps1` does not exist.

- [ ] **Step 3: Implement the minimal publisher script**

Probe through `cmd.exe /d /c`, redirect expected native stderr to a temporary file, and explicitly branch on `0`, `1`, or another exit code. Existing releases upload with `--clobber` then edit title/latest; missing releases use `gh release create --generate-notes --verify-tag`.

- [ ] **Step 4: Wire the test and publisher into the release workflow**

Run the PowerShell test before building. Replace the inline `gh release view` block with the script invocation while preserving all signing and signature-verification steps.

- [ ] **Step 5: Verify GREEN and workflow regression tests**

Run: `powershell -NoProfile -File .github/tests/Test-Publish-GitHubRelease.ps1`

Run: `.venv/bin/python -m unittest server.tests.test_release_workflow -v`

Expected: all tests pass.

### Task 2: Fixed-operation Local Service generation boundary

**Files:**
- Modify: `windows-agent/src/AppGuard.Service/RuleWorkerJob.cs`
- Modify: `windows-agent/src/AppGuard.Service/RuleWorkerClient.cs`
- Modify: `windows-agent/src/AppGuard.Service/RuleWorkerService.cs`
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `windows-agent/scripts/New-RuleFragment.ps1`
- Create: `windows-agent/scripts/New-WorkerPolicy.ps1`
- Create: `windows-agent/scripts/Install-GeneratedPolicy.ps1`
- Create: `server/tests/test_0180_rule_worker.py`

**Interfaces:**
- Consumes: `RuleWorkerClient.GenerateAsync(string operation, string sourcePath, string canonicalOutputPath, CancellationToken)`.
- Produces: `RuleWorkerResult` with `operation`, `rule_count`, `rule_mode`, `elapsed_seconds`, sanitized `error`, and file metadata; fixed unsigned XML output copied into the canonical protected directory.

- [ ] **Step 1: Write failing worker-contract tests**

Assert that all four operations are allowlisted, output names are fixed internally, request JSON has no script/output/install parameters, worker scripts contain no `CiTool`, `ConvertFrom-CIPolicy`, or administrator assertion, and PolicyHelper foreground paths no longer invoke the legacy all-in-one scripts.

- [ ] **Step 2: Run the worker tests and confirm RED**

Run: `.venv/bin/python -m unittest server.tests.test_0180_rule_worker -v`

Expected: FAIL because `primary_allow` and `deny_policy` are not accepted.

- [ ] **Step 3: Extend the closed worker contract**

Use a single operation allowlist and operation-to-output mapping. Validate GUID directory identity, basename input, canonical input containment, fixed worker output, positive rule count, and result operation equality before LocalSystem copies XML.

- [ ] **Step 4: Implement generation-only foreground PowerShell**

`New-WorkerPolicy.ps1` implements existing primary ProductName/FilePublisher/Hash fallback and existing deny product-family/per-file fallback, writes only unsigned multiple-policy XML inside the job directory, and returns compact JSON with mode/count/metadata.

- [ ] **Step 5: Implement LocalSystem post-processing and installation**

`Install-GeneratedPolicy.ps1` asserts administrator context, validates the staged XML in the protected policy directory, applies policy name/ID/base metadata for allow policies or deny rule options for deny policies, converts to CIP, calls `CiTool --update-policy` and `--refresh`, verifies the installed policy, and returns JSON.

- [ ] **Step 6: Route foreground approval and deny through the worker**

Keep `_policyGenerationGate` and foreground priority. Call the worker first, then call only the LocalSystem install helper. Preserve existing `SupplementalResult` fields and background bundle queuing.

- [ ] **Step 7: Verify GREEN and the existing approval/worker suites**

Run: `.venv/bin/python -m unittest server.tests.test_0180_rule_worker server.tests.test_0163_approval_pipeline server.tests.test_0165_localservice_rule_worker -v`

Expected: all tests pass.

### Task 3: Background retry state and bounded diagnostics

**Files:**
- Modify: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs`
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Modify: `windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs`
- Create: `server/tests/test_0180_background_retry.py`

**Interfaces:**
- Produces: `BackgroundPolicyQueueStatus` with `Pending`, `Failed`, `Status`, `OldestPendingAt`, and a bounded `LastError`.
- Produces: `BackgroundPolicyRetryResult RetryFailedWork()` with reset rule/bundle counts.
- Heartbeat fields: `background_policy_error`, `background_policy_oldest_at`.

- [ ] **Step 1: Add failing C# behavior cases and Python integration assertions**

Seed a snapshot containing failed, ready, installed, queued, and processing records. Assert retry resets only failed records to queued with attempts zero/error cleared, and queue diagnostics choose the oldest pending timestamp and most recently updated failed error capped at 1000 characters.

- [ ] **Step 2: Run tests and confirm RED**

Run: `dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release`

Run: `.venv/bin/python -m unittest server.tests.test_0180_background_retry -v`

Expected: FAIL because the retry/status contracts do not exist.

- [ ] **Step 3: Implement retry and diagnostics in the endpoint store**

Reset only status `failed`; leave `ready`/`installed` untouched. Derive pending/failed/status, oldest pending timestamp, and latest failed error from a single locked snapshot.

- [ ] **Step 4: Handle the fixed retry command and heartbeat fields**

Add `retry_background_policy` to `AgentWorker`, return reset counts in command completion, and send the two optional diagnostic fields on every heartbeat.

- [ ] **Step 5: Verify GREEN**

Run both commands from Step 2 and confirm all cases pass.

### Task 4: Server persistence, authorization, and retry UI

**Files:**
- Modify: `server/app.py`
- Extend: `server/tests/test_0180_background_retry.py`

**Interfaces:**
- Database: nullable `devices.background_policy_error` and `devices.background_policy_oldest_at`.
- Route: `POST /admin/devices/{device_id}/background-policy/retry`.
- Command payload: `{ "requested_by": principal.username }` only.

- [ ] **Step 1: Write failing server behavior tests**

Test optional heartbeat storage, older-heartbeat compatibility, cross-tenant denial, non-approver denial, active-command redirect, exact command payload, audit event, and button visibility only for authorized viewers with failed work and a free command queue.

- [ ] **Step 2: Run and confirm RED**

Run: `.venv/bin/python -m unittest server.tests.test_0180_background_retry -v`

Expected: FAIL because columns, route, and UI do not exist.

- [ ] **Step 3: Add non-destructive schema and heartbeat persistence**

Add optional Pydantic fields, `ensure_column` calls, and COALESCE updates. Escape and display the bounded error and oldest timestamp.

- [ ] **Step 4: Add tenant-scoped approver retry route**

Call `require_approver`, fetch the device, call `require_org_access`, reject/redirect when `active_device_command` is present, queue exactly one fixed command, and record `background_policy_retry_queued`.

- [ ] **Step 5: Render retry diagnostics and conditional button**

Show counts, error, oldest pending time, and the retry form only when failures exist, the principal can approve, and no active endpoint command exists.

- [ ] **Step 6: Verify GREEN and the complete server suite**

Run: `.venv/bin/python -m unittest server.tests.test_0180_background_retry -v`

Run: `.venv/bin/python -m unittest discover -s server/tests -q`

Expected: all tests pass.

### Task 5: Conservative Rule Worker job cleanup

**Files:**
- Modify: `windows-agent/src/AppGuard.Service/RuleWorkerService.cs`
- Extend: `server/tests/test_0180_rule_worker.py`

**Interfaces:**
- Produces: startup cleanup limited to job directories older than seven days that contain `result.json`, or that contain neither a publishable request nor a result.

- [ ] **Step 1: Write failing cleanup contract tests**

Assert recent request-without-result jobs are preserved, successful consumed jobs remain client-deleted, old completed failed jobs are deleted on worker startup, old unpublished abandoned directories are deleted, and cache/policy roots are never enumerated by cleanup.

- [ ] **Step 2: Run and confirm RED**

Run: `.venv/bin/python -m unittest server.tests.test_0180_rule_worker -v`

Expected: FAIL because startup cleanup is absent.

- [ ] **Step 3: Implement narrowly scoped startup cleanup**

Enumerate only direct child directories under `RuleWorkerJobsDirectory`, compare UTC last-write time to seven days, preserve any recent directory, and log each removal/failure without stopping the worker.

- [ ] **Step 4: Verify GREEN**

Run the command from Step 2 and confirm all cases pass.

### Task 6: Narrow .NET extraction classification

**Files:**
- Create: `windows-agent/src/AppGuard.Core/LearnedPathClassifier.cs`
- Modify: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Modify: `windows-agent/src/AppGuard.Core/InstallationLearningReconciler.cs`
- Modify: `windows-agent/src/AppGuard.Core/InstallationModeModels.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Modify: `windows-agent/src/AppGuard.Service/InstallationModeManager.cs`
- Modify: `windows-agent/tests/AppGuard.Core.BehaviorTests/Program.cs`
- Create: `server/tests/test_0180_dotnet_ephemeral.py`

**Interfaces:**
- Produces: `LearnedPathClassifier.IsExpectedDotNetExtraction(string path)`.
- Adds: `LearningPreparationStats.IgnoredEphemeral`, `InstallationLearningPlan.IgnoredEphemeralCount`, and `InstallationFinalizationResult.IgnoredEphemeralCount`.

- [ ] **Step 1: Write failing classifier and finalization cases**

Cover user temp and Windows temp positives, case-insensitive `.NET`, `..` escape rejection, missing app/bundle/child segments, NSIS `nsh*.tmp`, MSI paths, arbitrary temp paths, and names containing `.NET`. Prove mixed usable+ephemeral results do not warn and ephemeral-only learning fails with no usable rule.

- [ ] **Step 2: Run and confirm RED**

Run: `dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release`

Run: `.venv/bin/python -m unittest server.tests.test_0180_dotnet_ephemeral -v`

Expected: FAIL because the classifier and counters do not exist.

- [ ] **Step 3: Implement canonical Windows path classification**

Normalize separators, reject traversal, recognize only `C:\Users\<user>\AppData\Local\Temp` and `%SystemRoot%\Temp` roots, require `.net`, non-empty app and bundle segments, and at least one child segment.

- [ ] **Step 4: Apply classifier before missing-file handling**

Count recognized extraction children as ignored ephemeral, never queue a rule/reference, and do not increment unpreparable/skipped counts.

- [ ] **Step 5: Preserve safe zero-rule failure and diagnostics**

Report observed/candidate/ignored/skipped/installed separately. A mixed valid session remains completed without warnings; any non-empty session with zero usable rules still fails before Enforcement finalization claims success.

- [ ] **Step 6: Verify GREEN and installation regressions**

Run both commands from Step 2 plus `.venv/bin/python -m unittest server.tests.test_0172_installation_learning -v`.

Expected: all tests pass.

### Task 7: Version surfaces and release documentation

**Files:**
- Create: `0.18.0-FEATURES.txt`
- Modify: `README.md`
- Modify: all version-bearing server, service, tray, installer, build, upgrade, workflow, and version-test files identified by `rg '0\.17\.2'`.
- Modify: `server/tests/test_version_surfaces.py`

**Interfaces:**
- Produces: one consistent semantic version `0.18.0` across shipped artifacts and server responses.

- [ ] **Step 1: Change the version test to expect 0.18.0 and confirm RED**

Run: `.venv/bin/python -m unittest server.tests.test_version_surfaces -v`

Expected: FAIL while product files still report 0.17.2.

- [ ] **Step 2: Update every shipped version surface and documentation**

Preserve historical release notes while adding the consolidated feature summary, rollback baseline, upgrade expectations, and runtime acceptance checklist.

- [ ] **Step 3: Verify GREEN and scan for stale current-version literals**

Run: `.venv/bin/python -m unittest server.tests.test_version_surfaces -v`

Run: `rg -n '0\.17\.2' README.md server windows-agent .github --glob '!server/tests/test_0172_*'`

Expected: only historical 0.17.2 references remain.

### Task 8: Full verification and source packaging

**Files:**
- No production files beyond fixes required by verification.
- Create outside Git history: `/workspace/scratch/917436b8bb75/AppControlManager-0.18.0-source.zip`

**Interfaces:**
- Produces: complete source ZIP rooted at `AppControlManager-0.18.0/` without `.git`, `.worktrees`, `.venv`, `bin`, `obj`, `__pycache__`, or build outputs.

- [ ] **Step 1: Run the complete Python suite**

Run: `.venv/bin/python -m unittest discover -s server/tests -q`

- [ ] **Step 2: Run .NET behavior tests and builds**

Run: `dotnet run --project windows-agent/tests/AppGuard.Core.BehaviorTests/AppGuard.Core.BehaviorTests.csproj -c Release`

Run: `dotnet build windows-agent/AppControlManager.sln -c Release`

Run: `dotnet publish windows-agent/src/AppGuard.Service/AppGuard.Service.csproj -c Release -r win-x64 --self-contained true`

Run: `dotnet publish windows-agent/src/AppGuard.Tray/AppGuard.Tray.csproj -c Release -r win-x64 --self-contained true`

Run: `dotnet publish windows-agent/src/AppControlManager.Installer/AppControlManager.Installer.csproj -c Release -r win-x64 --self-contained true`

- [ ] **Step 3: Validate repository hygiene**

Run: `git diff --check`

Run: `git status --short`

Run: YAML parse validation for `.github/workflows/*.yml`.

- [ ] **Step 4: Review every spec requirement against the diff**

Confirm release probing, four worker operations, LocalSystem-only install, retry isolation, tenant controls, cleanup scope, .NET negatives, zero-rule failure, version surfaces, and rollback docs are each represented by code plus tests.

- [ ] **Step 5: Build and inspect the complete source ZIP**

Use `git archive` from the release worktree plus the uncommitted 0.18.0 changes, or a clean staging directory copied with explicit exclusions. List the archive root and verify required files are present and excluded paths absent.
