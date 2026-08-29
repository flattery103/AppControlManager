# 0.18.1 Learning Noise Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve transient learning inputs and stop normal file disappearance from presenting as production failure or repeated endpoint prompts.

**Architecture:** A service-side 3076 watcher writes non-executable protected cache copies keyed by event record ID. Background preparation resolves live path first and cached copy second; a precise `expired` terminal state handles inputs unavailable through either path.

**Tech Stack:** .NET 10 Windows service/tray, Windows Code Integrity event log, Python unittest regression suite.

**Spec:** `docs/superpowers/specs/2026-08-29-learning-noise-cleanup-design.md`

## Global Constraints

- No blanket TEMP allow or writable-path protection relaxation.
- Preserved binaries are rule-generation inputs only and are never executed.
- Only the exact missing-representative condition is neutralized.
- Work inline; do not push, tag, or modify GitHub state.

---

### Task 1: Protected learning input cache

**Files:**
- Create: `windows-agent/src/AppGuard.Service/LearningFileCache.cs`
- Create: `windows-agent/src/AppGuard.Service/LearningEventWatcher.cs`
- Modify: `windows-agent/src/AppGuard.Service/EventCollector.cs`
- Modify: `windows-agent/src/AppGuard.Service/Program.cs`
- Modify: `windows-agent/src/AppGuard.Core/Paths.cs`
- Test: `server/tests/test_0181_learning_noise.py`

- [ ] Write and run failing wiring/behavior tests.
- [ ] Add the bounded cache, public event conversion boundary, and 3076 watcher.
- [ ] Resolve live representatives before protected cached copies.
- [ ] Run the focused tests.

### Task 2: Neutral expiration lifecycle

**Files:**
- Modify: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs`
- Test: `server/tests/test_0181_learning_noise.py`

- [ ] Write and run failing lifecycle tests.
- [ ] Add `expired`, exact legacy migration, and a non-retryable transition.
- [ ] Catch only `FileNotFoundException` as expiration.
- [ ] Confirm queue status and Retry exclude expired work.

### Task 3: Endpoint prompt grouping and release surfaces

**Files:**
- Modify: `windows-agent/src/AppGuard.Tray/TrayContext.cs`
- Modify: version surfaces and release documentation.
- Test: `server/tests/test_0181_learning_noise.py`
- Test: `server/tests/test_version_surfaces.py`

- [ ] Write and run failing prompt/version tests.
- [ ] Add two-minute identity deduplication and longer related-component grouping.
- [ ] Update all version surfaces to 0.18.1 and document security behavior.
- [ ] Run focused and complete verification, then package the full source tree.
