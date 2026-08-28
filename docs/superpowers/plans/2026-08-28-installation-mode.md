# Installation Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add administrator-approved, user-activated timed Installation Mode plus manual administrator start, with a locally enforced timer and automatic return to Enforcement.

**Architecture:** Store installation requests/sessions on the server, queue validated start/end commands, and persist authoritative active-mode timing on the endpoint. During an installation window the existing Learning/Audit policy and Local Service rule worker prepare only the new delta; completion installs a new cumulative Installation supplemental rather than replacing the existing learned baseline, then restores the base policy to Enforcement. If delta finalization fails, a force-enforcement fallback restores Enforcement anyway and records the unresolved result.

**Tech Stack:** FastAPI + SQLite server, C#/.NET Windows service and WinForms tray, PowerShell ConfigCI/WDAC helpers, Python unittest regression suite.

**Spec:** `docs/superpowers/specs/2026-08-28-installation-mode-design.md`

## Global Constraints

- Release version is `0.17.0`.
- User-requested Installation Mode approval does not alter enforcement until the endpoint user clicks **Start Installation**.
- Approved user installation requests expire if not activated within four hours.
- Default duration is 15 minutes; supported presets are 15, 30, 60; custom duration is 1-240 minutes.
- Active Installation Mode expiration is enforced locally and survives server/browser loss and service restart.
- Existing learned authorization remains in place; installation completion adds a supplemental delta and must not replace the prior learned baseline.
- Failure to finalize new learned rules must still restore Enforcement.
- Endpoint users can request/start only administrator-approved installation sessions on their own enrolled device.
- Existing Request Access and explicit block behavior remains unchanged.
- `.NET` single-file extraction classification and approval-policy lifecycle cleanup remain out of scope.

---

### Task 1: Server installation request lifecycle and command contract

**Files:**
- Modify: `server/app.py`
- Create: `server/tests/test_0170_installation_mode.py`

**Interfaces:**
- Produces SQLite `installation_requests` lifecycle records.
- Produces agent APIs: `POST /api/installations`, `GET /api/installations`, `POST /api/installations/{id}/start`, `POST /api/installations/{id}/finish`, `POST /api/installations/{id}/report`.
- Produces validated commands `start_installation_mode` and `end_installation_mode`.

- [ ] **Step 1: Write failing server tests** covering additive schema, four-hour approval expiry, duration validation, no command on admin approval, command queued only after endpoint start, manual start command, endpoint/device ownership, and installation report state transitions.
- [ ] **Step 2: Run `python -m unittest server.tests.test_0170_installation_mode -v` and verify the new tests fail.**
- [ ] **Step 3: Add `installation_requests` schema and Pydantic request/report models.**
- [ ] **Step 4: Add agent-authenticated create/list/start/finish/report endpoints with device ownership checks and request-status guards.**
- [ ] **Step 5: Extend `ALLOWED_AGENT_COMMANDS`/`validate_agent_command` for `start_installation_mode` and `end_installation_mode`, validating request IDs and 1-240 minute durations.**
- [ ] **Step 6: Update command completion so start/end failures are reflected in the linked installation record without weakening normal command replay/claim behavior.**
- [ ] **Step 7: Re-run the Task 1 tests and verify they pass.**

### Task 2: Endpoint timed installation mode and enforcement fallback

**Files:**
- Create: `windows-agent/src/AppGuard.Core/InstallationModeModels.cs`
- Modify: `windows-agent/src/AppGuard.Core/Paths.cs`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Create: `windows-agent/src/AppGuard.Service/InstallationModeStore.cs`
- Create: `windows-agent/src/AppGuard.Service/InstallationModeManager.cs`
- Modify: `windows-agent/src/AppGuard.Service/Program.cs`
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `windows-agent/src/AppGuard.Service/ApiClient.cs`
- Create: `windows-agent/scripts/Force-Enforcement.ps1`
- Test: `server/tests/test_0170_installation_mode.py`

**Interfaces:**
- `InstallationModeManager.StartAsync(long requestId, int durationMinutes, string trigger, string actor, CancellationToken)` enters Learning/Audit and persists local deadline.
- `InstallationModeManager.EndAsync(string reason, CancellationToken)` finalizes a delta supplemental and returns to Enforcement.
- `InstallationModeManager.CheckExpirationAsync(CancellationToken)` ends expired windows locally.
- `InstallationModeStore` persists active/deadline/report state in `C:\ProgramData\AppControlManager\installation-mode.json`.

- [ ] **Step 1: Extend failing tests with source-contract assertions for persistent local state, maintenance-loop expiry checks, cumulative supplemental installation, and force-enforcement fallback.**
- [ ] **Step 2: Run the targeted tests and verify failure.**
- [ ] **Step 3: Add installation-mode models/store/path with atomic file replacement and recovery-safe defaults.**
- [ ] **Step 4: Add `PolicyHelper.FinalizeInstallationModeAsync` that collects only events since `learning_started`, prepares/generates missing fragments through the Local Service rule worker, installs them with `Install-MergedSupplemental.ps1` named `AppControl Manager Installation <requestId>`, and then flips the base policy to Enforcement. Existing learned baseline policies are not removed.**
- [ ] **Step 5: Add `Force-Enforcement.ps1` and `PolicyHelper.ForceEnforcementAsync`; it removes Audit option 3, updates/refreshes the base policy, and updates local learning state without requiring new fragments.**
- [ ] **Step 6: Implement `InstallationModeManager` with a semaphore so start/end/expiry cannot overlap. On finalization exception, run force enforcement, persist/report a failed-but-enforced result, and clear active mode.**
- [ ] **Step 7: Register the manager/store in DI, process start/end commands in `AgentWorker`, and call expiration/report retry from the independent maintenance loop.**
- [ ] **Step 8: Re-run targeted tests and verify pass.**

### Task 3: Endpoint Request Installation and approved-start UX

**Files:**
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Modify: `windows-agent/src/AppGuard.Service/LocalRequestServer.cs`
- Modify: `windows-agent/src/AppGuard.Service/ApiClient.cs`
- Modify: `windows-agent/src/AppGuard.Tray/RequestForm.cs`
- Modify: `windows-agent/src/AppGuard.Tray/SessionRequestForm.cs`
- Modify: `windows-agent/src/AppGuard.Tray/TrayContext.cs`
- Create: `windows-agent/src/AppGuard.Tray/InstallationApprovalForm.cs`
- Create: `windows-agent/src/AppGuard.Tray/InstallationModeForm.cs`
- Test: `server/tests/test_0170_installation_mode.py`

**Interfaces:**
- Pipe actions `request_installation`, `request_installation_session`, `start_installation`, `finish_installation`.
- Pipe status includes installation request history and local installation-mode snapshot.

- [ ] **Step 1: Add failing source-contract tests asserting both blocked popup variants expose `Request Installation`, approved installation popup includes `Start Installation`/`Not Now`, and active mode form includes countdown/early finish.**
- [ ] **Step 2: Run targeted tests and verify failure.**
- [ ] **Step 3: Add installation request/status/response models and ApiClient methods.**
- [ ] **Step 4: Extend LocalRequestServer to submit installation requests from preserved blocked metadata, choose the primary EXE for grouped sessions, start approved requests through the server, finish active sessions, and return installation state in status polling.**
- [ ] **Step 5: Add `Request Installation` to single and grouped blocked forms without changing Request Access behavior.**
- [ ] **Step 6: Extend TrayContext polling to detect newly approved installation requests, show one approval form, start only on the user's button click, and show active countdown/finish form.**
- [ ] **Step 7: Re-run targeted tests and verify pass.**

### Task 4: Administrator installation-request and device controls

**Files:**
- Modify: `server/app.py`
- Test: `server/tests/test_0170_installation_mode.py`

**Interfaces:**
- Admin routes `POST /admin/installations/{id}/approve`, `/deny`, `/admin/devices/{id}/installation-mode/start`, `/end`.
- Device detail and request center render installation status distinctly.

- [ ] **Step 1: Add failing tests for distinct Installation Request UI, duration selector, four-hour activation text, manual device controls, active mode banner/end action, and device-page redirects.**
- [ ] **Step 2: Run targeted tests and verify failure.**
- [ ] **Step 3: Render pending/recent Installation Requests separately in the request center with Approve Installation and Deny actions.**
- [ ] **Step 4: Add admin approval/deny routes; approval writes duration + four-hour activation deadline but queues no endpoint mode command.**
- [ ] **Step 5: Add manual device start route that creates an admin-source installation session and queues start immediately, plus end route for active/starting sessions.**
- [ ] **Step 6: Add device-page Installation Mode controls/banner and a browser countdown based on server-reported `ends_at`; all device mode actions return to `/devices/{device_id}`.**
- [ ] **Step 7: Re-run targeted tests and verify pass.**

### Task 5: Release surfaces, regression verification, and package

**Files:**
- Modify: `server/app.py`
- Modify: `windows-agent/Build.ps1`
- Modify: Windows project/runtime version fallbacks containing `0.16.5`
- Modify: `README.md`
- Create: `0.17.0-FEATURES.txt`
- Modify: `server/tests/test_version_surfaces.py` if necessary
- Test: all `server/tests`

**Interfaces:**
- Release artifacts remain compatible with existing GitHub Actions signing and automatic server agent import.

- [ ] **Step 1: Add/adjust failing version-surface test expectations for `0.17.0`.**
- [ ] **Step 2: Update every runtime/build/server release surface to `0.17.0` and write release notes describing Installation Mode, four-hour activation expiry, local timer, cumulative supplemental behavior, and force-enforcement safety.**
- [ ] **Step 3: Run `python -m unittest discover -s server/tests -v` and require zero failures.**
- [ ] **Step 4: Parse workflow YAML, run Bash syntax checks, Python compile checks, line-ending checks, and source-archive `core.autocrlf=true` regression.**
- [ ] **Step 5: Build `AppControlManager-0.17.0-source.zip` with deterministic top-level directory, compute `.sha256`, verify the checksum, and retain both in `/Threatlocker Clone/`.**
