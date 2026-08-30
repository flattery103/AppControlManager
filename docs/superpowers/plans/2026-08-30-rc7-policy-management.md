# RC7 Policy Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make bundled approvals manageable and make multi-policy deletion asynchronous, observable, and automatic after endpoint cleanup.

**Architecture:** Keep endpoint WDAC commands serialized by the existing agent queue. Normalize policy identifiers at the server boundary, group approval components by installed policy, and represent deletion intent on `scoped_policies` until cleanup completes. A shared finalizer soft-deletes requested policies only when no active commands or installed endpoint layers remain.

**Tech Stack:** FastAPI, SQLite, Python unittest, existing Windows agent command protocol.

**Spec:** Approved RC7 scope from the 2026-08-30 project conversation.

## Global Constraints

- Preserve endpoint-side serialized WDAC operations.
- Do not delete policy records until endpoint cleanup is complete.
- Preserve audit history and organization authorization boundaries.
- Accept braced and unbraced policy GUIDs.

---

### Task 1: Bundle-aware approval actions

**Files:**
- Modify: `server/app.py`
- Test: `server/tests/test_100rc_policy_management.py`

- [x] Write tests proving braced GUIDs show revoke actions, Block is independent of GUID format, and bundle members render as one policy row.
- [x] Run the focused tests and confirm they fail on RC6.
- [x] Normalize action eligibility and group approval rows by installed policy/request.
- [x] Run the focused tests and confirm they pass.

### Task 2: Asynchronous bulk policy deletion

**Files:**
- Modify: `server/app.py`
- Test: `server/tests/test_100rc_policy_management.py`

- [x] Write tests for multi-select deletion requests, pending-deletion display, idempotency, and automatic finalization only after cleanup.
- [x] Run the focused tests and confirm they fail.
- [x] Add deletion-request migration fields, bulk POST handling, cleanup-state calculation, and finalization after command completion.
- [x] Replace raw HTTP cleanup errors with redirects and visible status notices.
- [x] Run the focused tests and confirm they pass.

### Task 3: RC7 release surfaces and verification

**Files:**
- Create: `1.0.0-RC7-FIXES.txt`
- Modify: version-bearing server, agent, workflow, README, and operational guide files.
- Test: `server/tests/test_version_surfaces.py`

- [x] Change the version test to `1.0.0-rc.7` and confirm failure.
- [x] Update all current version surfaces and release notes.
- [x] Run all server tests, Windows behavior tests where available, and `git diff --check`.
- [x] Commit and create a full prefixed source ZIP with a SHA-256 checksum.
