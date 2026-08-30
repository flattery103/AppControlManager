# RC8 Policy Revocation and Offboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make revocation predictable under a learned base policy, make cleanup idempotent, expose precise device work status, and completely offboard AppControl Manager without touching third-party WDAC policy.

**Architecture:** Endpoint policy removal becomes idempotent for Windows policy-not-found results. Server cleanup counts only revoke/unblock work and reconciles legacy completed removals. A combined Revoke and Block workflow queues the deny before supplemental revocation. Successful offboarding removes all AppControl Manager-named WDAC policies locally, deletes both services and local state, then atomically purges server operational records while retaining one audit event.

**Tech Stack:** FastAPI, SQLite, Python unittest, C#/.NET service, PowerShell, CiTool.

**Spec:** Approved RC8 scope in the 2026-08-30 project conversation.

## Global Constraints

- Never remove Microsoft, Intune, or third-party WDAC policies.
- Remove AppControl Manager base policies last.
- Preserve one server audit event proving offboarding occurred.
- Serialize endpoint WDAC commands through the existing command queue.
- Publish the release initially as Latest so the server GUI detects it.

---

### Task 1: Idempotent cleanup and legacy reconciliation

**Files:**
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `server/app.py`
- Test: `windows-agent/tests/AppGuard.Core.BehaviorTests/PolicyRemovalBehavior.cs`
- Test: `server/tests/test_100rc_policy_management.py`

- [ ] Add failing tests for policy-not-found success, cleanup command filtering, and braced legacy records.
- [ ] Treat CiTool `0x80070002` as already removed while retaining all other failures.
- [ ] Count only failed `revoke_approval` and `unblock_file` commands as deletion failures.
- [ ] Reconcile legacy approval state from completed removal commands.
- [ ] Run focused tests.

### Task 2: Revocation semantics and device status

**Files:**
- Modify: `server/app.py`
- Test: `server/tests/test_100rc_policy_management.py`
- Test: `server/tests/test_operational_reporting.py`

- [ ] Add failing tests for Revoke and Block ordering, post-revocation base-policy warning, and precise update health labels.
- [ ] Add a combined action that creates/queues an explicit deny before queuing supplemental revocation.
- [ ] Keep revoked applications visible when baseline authorization may remain, with Block available from retained history.
- [ ] Prefer Downloading, Staging, Activating, or Installing over generic Working on device detail.
- [ ] Clear the same-release failure latch only for an explicit manual retry assignment.
- [ ] Run focused tests.

### Task 3: Complete offboarding

**Files:**
- Modify: `windows-agent/scripts/Apply-AgentUninstall.ps1`
- Modify: `server/app.py`
- Test: `.github/tests/Test-AgentUninstall.ps1`
- Test: `server/tests/test_100rc_offboarding.py`

- [ ] Add failing tests for AppControl Manager-only policy selection, base-last ordering, both service removals, local-state removal, and server purge.
- [ ] Make already-absent AppControl Manager policy removal idempotent.
- [ ] Remove the main service, Rule Worker, tray startup, program files, and ProgramData.
- [ ] On successful offboard report, preserve a minimal audit event and purge all operational device records automatically.
- [ ] Run focused tests.

### Task 4: RC8 release and verification

**Files:**
- Create: `1.0.0-RC8-FIXES.txt`
- Modify: all current version surfaces and operational documentation.

- [ ] Update version tests to `1.0.0-rc.8` and observe failure.
- [ ] Update current server, agent, installer, workflow, and documentation version surfaces.
- [ ] Run the complete server test suite, local script checks, and `git diff --check`.
- [ ] Commit and create a prefixed source ZIP with SHA-256 verification.
