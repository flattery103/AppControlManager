# Local Service Rule Worker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route 0.16.5 background and learned ConfigCI fragment generation through a dedicated Local Service worker while retaining all privileged WDAC installation in the LocalSystem agent.

**Architecture:** Register the existing signed service executable a second time with `--rule-worker` under `NT AUTHORITY\LOCAL SERVICE`. The SYSTEM service submits tightly validated, file-based jobs containing a staged copy of the representative file; the Local Service worker generates only XML fragments, and SYSTEM validates/copies the result into the existing fragment cache.

**Tech Stack:** .NET 10 Windows Worker Service/C#, Windows PowerShell 5.1 ConfigCI cmdlets, Windows Service Control Manager, NTFS ACLs, JSON job files, existing Python unittest regression suite.

**Spec:** `docs/superpowers/specs/2026-08-28-localservice-rule-worker-design.md`

## Global Constraints

- 0.16.5 changes only background/learned rule-fragment generation; foreground approvals, deny rules, `.net` learning classification, and server redirect behavior are out of scope.
- Main `AppControlManager` service remains LocalSystem and remains the only policy install/remove/merge authority.
- `AppControlManagerRuleWorker` runs as `NT AUTHORITY\LocalService` and starts only the worker code path.
- Reuse the existing signed `AppControlManager.Service.exe`; do not add a third signed executable.
- Local Service gets access only to the secured RuleWorker job directory and fixed scripts under Program Files.
- 0.16.2 remains documented as rollback/reference baseline.

---

### Task 1: Lock the 0.16.5 worker contract with failing regression tests

**Files:**
- Create: `server/tests/test_0165_localservice_rule_worker.py`
- Test: `server/tests/test_0165_localservice_rule_worker.py`

**Interfaces:**
- Consumes: existing 0.16.4 source tree.
- Produces: static regression contract for worker mode, job validation, PolicyHelper routing, lifecycle scripts, and version surfaces.

- [ ] **Step 1: Write failing tests** asserting the design requirements above, including source checks for `--rule-worker`, `AppControlManagerRuleWorker`, `NT AUTHORITY\\LocalService`, fixed `fragment.xml`, allowlisted kinds, worker client usage, removal of `Assert-Administrator` from `New-RuleFragment.ps1`, and stop/start/delete lifecycle handling.
- [ ] **Step 2: Run `python3 -m unittest server.tests.test_0165_localservice_rule_worker -v`** and verify it fails because 0.16.4 has no worker implementation.
- [ ] **Step 3: Commit the RED contract** with `git add server/tests/test_0165_localservice_rule_worker.py && git commit -m "test: define local service rule worker contract"`.

### Task 2: Add the constrained Rule Worker job model and Local Service execution mode

**Files:**
- Modify: `windows-agent/src/AppGuard.Core/Paths.cs`
- Create: `windows-agent/src/AppGuard.Service/RuleWorkerJob.cs`
- Create: `windows-agent/src/AppGuard.Service/RuleWorkerService.cs`
- Modify: `windows-agent/src/AppGuard.Service/Program.cs`
- Modify: `windows-agent/scripts/New-RuleFragment.ps1`
- Test: `server/tests/test_0165_localservice_rule_worker.py`

**Interfaces:**
- Produces: `RuleWorkerRequest`/`RuleWorkerResult` JSON job types and `RuleWorkerService` that processes only staged product/hash jobs and fixed `fragment.xml` output.
- Consumes: `AppGuardPaths.RuleWorkerJobsDirectory`, `AppGuardPaths.ScriptsDirectory`.

- [ ] **Step 1: Implement worker paths and job DTOs** with fixed job-root semantics and no arbitrary script/output fields.
- [ ] **Step 2: Implement `RuleWorkerService`** to sequentially enumerate `request.json`, validate job ID/kind/basename paths, invoke `New-RuleFragment.ps1`, parse its JSON, and atomically write `result.json`.
- [ ] **Step 3: Add `--rule-worker` startup branch** so the worker service name is `AppControl Manager Rule Worker` and the normal API/command/updater dependencies are not registered in worker mode.
- [ ] **Step 4: Remove only `Assert-Administrator` from `New-RuleFragment.ps1`**; retain its generation-only behavior and all other privileged script checks.
- [ ] **Step 5: Run the 0.16.5 tests** and verify worker-mode tests pass while PolicyHelper/lifecycle tests remain RED.
- [ ] **Step 6: Commit** with `git add windows-agent/src windows-agent/scripts/New-RuleFragment.ps1 server/tests/test_0165_localservice_rule_worker.py && git commit -m "feat: add local service rule worker"`.

### Task 3: Route background and learned fragment generation through the worker

**Files:**
- Create: `windows-agent/src/AppGuard.Service/RuleWorkerClient.cs`
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `windows-agent/src/AppGuard.Service/Program.cs`
- Test: `server/tests/test_0165_localservice_rule_worker.py`

**Interfaces:**
- Produces: `Task<BackgroundRuleFragmentResult> RuleWorkerClient.GenerateAsync(string kind, string sourcePath, string canonicalOutputPath, CancellationToken ct)`.
- Consumes: `RuleWorkerRequest`/`RuleWorkerResult`; canonical `AppGuardPaths.RuleFragmentDirectory` cache.

- [ ] **Step 1: Implement `RuleWorkerClient`** to create a GUID job, copy the representative file using its original extension, atomically publish `request.json`, wait for `result.json`, validate success/rule count/fixed output, copy `fragment.xml` to the canonical SYSTEM-owned cache path, and clean a completed job.
- [ ] **Step 2: Register `RuleWorkerClient` only in normal agent mode.**
- [ ] **Step 3: Replace direct `RunPowerShellAsync(New-RuleFragment.ps1)` in `GenerateRuleFragmentCoreAsync`** with `RuleWorkerClient.GenerateAsync`; leave merge/install helpers unchanged under SYSTEM.
- [ ] **Step 4: Run `python3 -m unittest server.tests.test_0165_localservice_rule_worker -v`** and verify routing/security tests pass.
- [ ] **Step 5: Run `python3 -m unittest discover -s server/tests -v`** and resolve only regressions caused by this boundary change.
- [ ] **Step 6: Commit** with `git add windows-agent/src server/tests/test_0165_localservice_rule_worker.py && git commit -m "fix: generate rule fragments outside LocalSystem"`.

### Task 4: Install, update, rollback, and uninstall the worker safely

**Files:**
- Modify: `windows-agent/src/AppControlManager.Installer/Program.cs`
- Modify: `windows-agent/Upgrade-Agent.ps1`
- Modify: `windows-agent/scripts/Apply-AgentUpdate.ps1`
- Modify: `windows-agent/Uninstall-Agent.ps1`
- Test: `server/tests/test_0165_localservice_rule_worker.py`

**Interfaces:**
- Produces: service `AppControlManagerRuleWorker`, binary arguments `--rule-worker`, LocalService identity, automatic start, secured RuleWorker ACL.
- Consumes: same shared `AppControlManager.Service.exe` deployed by existing packaging.

- [ ] **Step 1: Add first-install worker directory ACL and service registration** using SID `S-1-5-19`/`NT AUTHORITY\\LocalService` without granting ordinary Users write access.
- [ ] **Step 2: Add manual-upgrade equivalent registration/repair** and start the worker.
- [ ] **Step 3: Update managed activation** to stop both services before replacing the shared executable, create/repair the worker and ACL, start worker then main service, and restore both on rollback.
- [ ] **Step 4: Update uninstall** to stop/delete both services while retaining ProgramData as before.
- [ ] **Step 5: Run the 0.16.5 lifecycle tests and full suite.**
- [ ] **Step 6: Commit** with `git add windows-agent server/tests/test_0165_localservice_rule_worker.py && git commit -m "feat: manage rule worker service lifecycle"`.

### Task 5: Advance release surfaces, signing checks, and package 0.16.5

**Files:**
- Modify: `windows-agent/Build.ps1`
- Modify: `windows-agent/src/AppGuard.Core/AppGuard.Core.csproj`
- Modify: `windows-agent/src/AppGuard.Service/AppGuard.Service.csproj`
- Modify: `windows-agent/src/AppGuard.Tray/AppGuard.Tray.csproj`
- Modify: `windows-agent/src/AppControlManager.Installer/AppControlManager.Installer.csproj`
- Modify: `.github/workflows/build-windows.yml`
- Modify: `README.md`
- Create: `0.16.5-FEATURES.txt`
- Modify: any other version surface identified by `server/tests/test_version_surfaces.py`
- Test: `server/tests/test_0165_localservice_rule_worker.py`, full `server/tests` suite.

**Interfaces:**
- Produces: version `0.16.5` source/package surfaces while signing the same Service and Tray payload set as 0.16.4.
- Consumes: existing Azure Artifact Signing release workflow.

- [ ] **Step 1: Move all release version defaults/fallbacks to `0.16.5`** and add release notes documenting Local Service generation and 0.16.2 rollback baseline.
- [ ] **Step 2: Confirm Build.ps1 still packages one shared Service executable and does not require a new signing artifact.**
- [ ] **Step 3: Run `python3 -m unittest discover -s server/tests -v`**, Python compile checks, Bash syntax checks, workflow YAML parse, LF checks, and source-version scans.
- [ ] **Step 4: Build `AppControlManager-0.16.5-source.zip` using a clean Git archive with `core.autocrlf=false`, verify extraction and SHA256, and copy the ZIP/SHA to `/mnt/data/appcontrol_0165/`.
- [ ] **Step 5: Retain the ZIP/SHA in Library `/Threatlocker Clone/`.**
