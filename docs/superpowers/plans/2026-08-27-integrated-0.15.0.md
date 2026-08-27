# AppControl Manager 0.15.0 Integrated Feature Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Produce one 0.15.0 source release that adds signed GitHub Release builds, server self-update UI, automatic matching agent-release import, and formalizes the already-present scoped policy/deployment features.

**Architecture:** Keep the existing monolithic FastAPI application stable and introduce one focused `release_management.py` helper module plus one CLI importer. Extend the shell updater to consume GitHub release assets and extend the GitHub workflow into build → sign → package → sign → verify → release stages.

**Tech Stack:** FastAPI, SQLite, Python 3 stdlib, Bash/systemd, PowerShell, .NET 10, GitHub Actions, Azure Artifact Signing.

**Spec:** `docs/superpowers/specs/2026-08-27-integrated-0.15.0-design.md`

## Global Constraints

- Product version is `0.15.0`.
- Reusable enrollment tokens remain reusable until manually disabled.
- Existing scoped policies and agent deployments remain backward compatible.
- Server self-update installation is global-admin-only.
- Release workflow must not publish unsigned Windows release artifacts.
- Final deep tenant/authorization audit remains deferred.

---

### Task 1: Release metadata and verified agent import helpers

**Files:**
- Create: `server/release_management.py`
- Create: `server/import-agent-release.py`
- Create: `server/tests/test_release_management.py`

**Interfaces:**
- Produces `GitHubReleaseInfo`, `fetch_latest_release()`, `verify_sha256_file()`, and `import_agent_release()`.
- CLI imports already-verified downloaded assets into the AppControl Manager DB/release directory idempotently.

- [x] Write failing tests for parsing GitHub release JSON, SHA256 verification, successful import, and duplicate import.
- [x] Run tests and confirm failures are due to missing module/functions.
- [x] Implement the minimal helper module and CLI.
- [x] Re-run tests until green.
- [x] Commit the task.

### Task 2: Server Updates UI and detached installer launch

**Files:**
- Modify: `server/app.py`
- Create: `server/tests/test_server_update_helpers.py`

**Interfaces:**
- Adds `/server-updates` and `/admin/server-updates/install`.
- Uses `fetch_latest_release()` for display and `systemd-run` to start `/opt/appcontrol-manager/update-from-github.sh --install` independently of uvicorn.

- [x] Write failing tests for server-update status formatting and global-admin navigation/route presence.
- [x] Run tests to confirm failure.
- [x] Add the UI, status/log helpers, navigation link, and detached updater launch.
- [x] Re-run tests and Python compile checks.
- [x] Commit the task.

### Task 3: GitHub updater imports matching agent artifacts

**Files:**
- Modify: `server/update-from-github.sh`
- Modify: `server/install-server.sh`
- Modify: `server/upgrade-server.sh`
- Create: `server/tests/test_updater_assets.py`

**Interfaces:**
- Updater requires source ZIP/SHA and, when present, downloads agent ZIP/SHA + installer/SHA from the same release.
- Calls installed `import-agent-release.py` after health validation.

- [x] Write failing static/behavior tests for required GitHub asset names and importer invocation.
- [x] Run tests to confirm failure.
- [x] Implement updater/importer installation changes.
- [x] Re-run tests and `bash -n` checks.
- [x] Commit the task.

### Task 4: Build-stage separation and Artifact Signing workflow

**Files:**
- Modify: `windows-agent/Build.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/build-windows.yml`
- Create: `windows-agent/Verify-Signatures.ps1`
- Create: `server/tests/test_release_workflow.py`

**Interfaces:**
- `Build.ps1 -Stage Prepare` publishes Service/Tray only.
- `Build.ps1 -Stage Package -RequireSignedPayload` packages already-signed Service/Tray and builds installer.
- `Verify-Signatures.ps1` fails if Authenticode status is not Valid.
- Release workflow authenticates with Azure OIDC and uses `azure/artifact-signing-action@v2`.

- [x] Write failing workflow/build-structure tests.
- [x] Run tests to confirm failure.
- [x] Refactor build stages and add signature verifier.
- [x] Update release workflow to build/sign/package/sign/verify/publish.
- [x] Re-run static tests/YAML parse checks.
- [x] Commit the task.

### Task 5: Versioning, feature documentation, packaging and verification

**Files:**
- Modify: `server/app.py`
- Modify: `README.md`
- Create: `0.15.0-FEATURES.txt`
- Modify version defaults in Windows build/project-facing text where applicable.

**Interfaces:**
- `/health` and UI report 0.15.0.
- Documentation identifies required Artifact Signing configuration and server-update workflow.

- [x] Write/version-check tests that fail while 0.13.1 remains.
- [x] Update all intended product version surfaces to 0.15.0 and documentation.
- [x] Run full Python tests, py_compile, Bash syntax, YAML parse, source scan, and ZIP integrity verification.
- [x] Create `AppControlManager-0.15.0-source.zip` and SHA256.
- [x] Commit the task and record final verification evidence.


## Verification Evidence

- `python3 -m unittest discover -s server/tests -v`: 18 tests passed.
- `python3 -m py_compile server/app.py server/release_management.py server/import-agent-release.py`: passed.
- `bash -n server/install-server.sh server/upgrade-server.sh server/update-from-github.sh`: passed.
- `.github/workflows/build-windows.yml` and `.github/workflows/release.yml`: parsed successfully with PyYAML.
- Operational version scan confirms 0.15.0; the single remaining 0.13.0 literal in `server/app.py` is the intentional compatibility threshold for command-claim enforcement.
- `git diff --check`: passed.
- Windows/.NET build and live Azure Artifact Signing were not executable in the Linux packaging environment because `dotnet`/PowerShell and Azure signing credentials are not present. GitHub Actions is the intended Windows signing/build validation environment.
