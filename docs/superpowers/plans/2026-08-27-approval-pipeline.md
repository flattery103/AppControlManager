# AppControl Manager 0.16.3 Approval Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make signed application approvals usable after one primary ConfigCI rule instead of waiting for every bundle component, while preparing auxiliary and Learning rules in the background and keeping 0.16.2 as the rollback/reference baseline.

**Architecture:** Keep ConfigCI as the supported rule generator, but move expensive repeated calls out of the user-facing path. The foreground approval generates and installs one primary ProductName-scoped FilePublisher rule, then queues auxiliary signer/product work as durable local rule-fragment jobs. A dedicated background loop generates reusable rule-fragment XML one item at a time, merges ready fragments into one request-specific supplemental policy, and reports that policy to the server. Learning uses the same fragment cache incrementally; Enable Enforcement prepares only missing delta fragments, merges the prepared set into a replacement learned baseline, installs it, verifies it, then removes obsolete AppControl Manager learned-baseline policies.

**Tech Stack:** .NET 10 Worker Service/C#, Windows PowerShell 5.1 ConfigCI cmdlets, CiTool.exe, FastAPI/Python, SQLite, JSON files under `C:\ProgramData\AppControlManager`, existing unittest regression suite.

**Spec:** `docs/superpowers/specs/2026-08-27-approval-pipeline-design.md`

## Global Constraints

- Version `0.16.2` is the explicit rollback/reference baseline. Do not overwrite or delete its retained source artifact.
- Do not broaden an approval to publisher-wide trust.
- Primary signed approvals prefer signer + ProductName FilePublisher rules; unsafe/missing ProductName uses conservative per-file fallback.
- Auxiliary approval work is restricted to the discovered application root and expected signer.
- Background ConfigCI work must never run concurrently with foreground ConfigCI work.
- Background work is processed one rule fragment at a time so a newly requested foreground approval waits for at most the currently-running fragment, not an entire bundle.
- Internal timestamps remain UTC.
- Reusable enrollment-token behavior is unchanged.
- Server schema changes for background state are additive only; 0.16.2 must be able to open the database and ignore the new tables/columns.
- A successful primary approval remains successful if background completion later fails.
- Enable Enforcement must not silently proceed if a learned rule required for the final baseline is unresolved.

## File Structure

**Create**

- `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs` — serializable rule-cache and background-bundle job models.
- `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs` — atomic durable JSON store for cache entries, request jobs, and learned references.
- `windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs` — one-at-a-time background rule generation, bundle merge/install, retry, and server reporting.
- `windows-agent/scripts/New-PrimaryApprovalPolicy.ps1` — foreground one-file ProductName/fallback supplemental policy generator and installer.
- `windows-agent/scripts/New-RuleFragment.ps1` — generate one reusable ProductName or hash rule fragment XML without installing it.
- `windows-agent/scripts/Install-MergedSupplemental.ps1` — merge cached fragment XML into one request-specific supplemental policy, convert, install, verify, and return JSON.
- `windows-agent/scripts/Install-LearnedBaselineFromFragments.ps1` — merge learned fragments into a replacement learned baseline, install/verify, then remove older learned baselines.
- `server/tests/test_0163_approval_pipeline.py` — 0.16.3 regression contract.

**Modify**

- `windows-agent/src/AppGuard.Core/Paths.cs` — durable cache/job paths.
- `windows-agent/src/AppGuard.Core/Models.cs` — heartbeat/background status and command-completion background metadata.
- `windows-agent/src/AppGuard.Service/Program.cs` — register background store/processor.
- `windows-agent/src/AppGuard.Service/PolicyHelper.cs` — primary-only foreground authorization, bundle identity grouping, policy-generation serialization, rule-fragment helpers.
- `windows-agent/src/AppGuard.Service/AgentWorker.cs` — fourth background loop, Learning-event enqueue, foreground priority flag, completion metadata.
- `windows-agent/src/AppGuard.Service/ApiClient.cs` — background policy result endpoint.
- `windows-agent/scripts/End-LearningAndEnforce.ps1` — final-delta wait + fragment-based baseline installation instead of rebuilding all rules.
- `windows-agent/scripts/Get-LearnedApplications.ps1` — preserve current snapshot format; add only fields required to form stable cache identity if absent.
- `windows-agent/scripts/Common.ps1` — shared ProductName safety and learned-baseline policy discovery/removal helpers.
- `server/app.py` — additive background tables/columns, result endpoint, request status display, revoke-all-linked-policy behavior, heartbeat diagnostics.
- `server/tests/test_version_surfaces.py`, `.github/workflows/build-windows.yml`, `windows-agent/Build.ps1`, project files, README, release notes — version 0.16.3 surfaces in final task.

---

### Task 1: Lock the 0.16.3 approval behavior in failing regression tests

**Files:**
- Create: `server/tests/test_0163_approval_pipeline.py`
- Modify later tasks only; do not change production code in this task.

**Interfaces:**
- Consumes: 0.16.2 source exactly as committed at `d7e1824` plus approved spec.
- Produces: failing textual/behavioral regression tests that define the 0.16.3 architecture before implementation.

- [ ] **Step 1: Write the failing regression test module**

Create `server/tests/test_0163_approval_pipeline.py` with tests equivalent to:

```python
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Release0163ApprovalPipelineTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding='utf-8')

    def test_foreground_approval_uses_primary_policy_builder_not_full_bundle_helper(self):
        text = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        self.assertIn('New-PrimaryApprovalPolicy.ps1', text)
        self.assertIn('QueueBackgroundBundle', text)
        self.assertNotIn('Building and installing the Windows App Control policy for {files.Length} file(s)', text)

    def test_primary_policy_prefers_product_name_filepublisher_for_safe_signed_file(self):
        text = self.text('windows-agent/scripts/New-PrimaryApprovalPolicy.ps1')
        self.assertIn('SpecificFileNameLevel ProductName', text)
        self.assertIn('Test-AppGuardProductFamilyCandidate', text)
        self.assertIn('ACM_STAGE primary-rule-generation', text)
        self.assertIn('ACM_STAGE primary-policy-install', text)

    def test_background_queue_is_durable_and_has_required_states(self):
        model = self.text('windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs')
        store = self.text('windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs')
        for state in ('queued', 'processing', 'ready', 'installed', 'superseded', 'failed'):
            self.assertIn(state, model.lower())
        self.assertIn('BackgroundPolicyQueuePath', self.text('windows-agent/src/AppGuard.Core/Paths.cs'))
        self.assertIn('.tmp.', store)
        self.assertIn('File.Move', store)

    def test_background_work_runs_in_a_separate_loop_and_is_serialized_with_foreground(self):
        worker = self.text('windows-agent/src/AppGuard.Service/AgentWorker.cs')
        helper = self.text('windows-agent/src/AppGuard.Service/PolicyHelper.cs')
        self.assertIn('RunBackgroundPolicyLoopAsync', worker)
        self.assertIn('Task.WhenAll', worker)
        self.assertIn('SemaphoreSlim', helper)
        self.assertIn('foreground', helper.lower())

    def test_background_fragment_generation_does_not_install_policy(self):
        text = self.text('windows-agent/scripts/New-RuleFragment.ps1')
        self.assertIn('New-CIPolicyRule', text)
        self.assertIn('New-CIPolicy', text)
        self.assertNotIn('CiTool.exe --update-policy', text)
        self.assertNotIn('ConvertFrom-CIPolicy', text)

    def test_request_bundle_install_merges_cached_fragments_into_one_supplemental(self):
        text = self.text('windows-agent/scripts/Install-MergedSupplemental.ps1')
        self.assertIn('Merge-CIPolicy', text)
        self.assertIn('ConvertFrom-CIPolicy', text)
        self.assertIn('CiTool.exe --update-policy', text)
        self.assertIn('ACM_STAGE background-policy-install', text)

    def test_learning_enforcement_consumes_prepared_fragments_and_only_generates_delta(self):
        text = self.text('windows-agent/scripts/End-LearningAndEnforce.ps1')
        self.assertIn('Install-LearnedBaselineFromFragments.ps1', text)
        self.assertIn('prepared=', text)
        self.assertIn('unprepared=', text)
        self.assertNotIn('New-LearnedBaselinePolicy.ps1', text)

    def test_learned_baseline_replacement_removes_old_baseline_only_after_new_install(self):
        text = self.text('windows-agent/scripts/Install-LearnedBaselineFromFragments.ps1')
        install = text.index('CiTool.exe --update-policy')
        remove = text.index('--remove-policy')
        self.assertLess(install, remove)
        self.assertIn('AppControl Manager Learned Baseline', text)

    def test_background_server_schema_is_additive_and_tracks_linked_policy_ids(self):
        text = self.text('server/app.py')
        self.assertIn('CREATE TABLE IF NOT EXISTS approval_background_policies', text)
        self.assertIn('/api/background-policies/report', text)
        self.assertIn('background_policy_status', text)
        self.assertNotIn('DROP TABLE', text)

    def test_revoke_queues_all_policy_layers_linked_to_same_request(self):
        text = self.text('server/app.py')
        self.assertIn('linked_policy_ids_for_request', text)
        self.assertIn('approval_background_policies', text)

    def test_rollback_baseline_is_documented(self):
        features = self.text('0.16.3-FEATURES.txt') if (ROOT / '0.16.3-FEATURES.txt').exists() else ''
        self.assertIn('0.16.2', features)
        self.assertIn('rollback', features.lower())


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run only the new module and verify RED**

Run:

```bash
python -m unittest server.tests.test_0163_approval_pipeline -v
```

Expected: multiple failures because the new files/classes/routes do not exist yet. Confirm failures are about the missing 0.16.3 behavior, not syntax/import errors in the test.

- [ ] **Step 3: Commit the RED tests**

```bash
git add server/tests/test_0163_approval_pipeline.py
git commit -m "test: define 0.16.3 approval pipeline contract"
```

---

### Task 2: Add durable rule-cache and background-job models/store

**Files:**
- Create: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Create: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Modify: `windows-agent/src/AppGuard.Core/Paths.cs`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- Produces `RuleCacheEntry`, `BackgroundBundleJob`, `LearningRuleReference`, `BackgroundPolicySnapshot` JSON-serializable models.
- Produces `BackgroundPolicyStore` methods:
  - `BackgroundPolicySnapshot Snapshot()`
  - `RuleCacheEntry UpsertProductCandidate(long? requestId, string ownerType, string publisher, string productName, string fileVersion, string representativePath)`
  - `RuleCacheEntry UpsertHashCandidate(long? requestId, string ownerType, string sha256, string representativePath)`
  - `BackgroundBundleJob QueueBundle(long requestId, long? scopedPolicyId, string applicationRoot, IReadOnlyList<BackgroundBundleMember> members, IEnumerable<string> requiredRuleKeys)`
  - `RuleCacheEntry? ClaimNextRule()`
  - `void MarkRuleReady(string cacheKey, string fragmentXmlPath, string? minimumFileVersion)`
  - `void MarkRuleFailed(string cacheKey, string error)`
  - `BackgroundBundleJob? ClaimReadyBundle()`
  - `void MarkBundleInstalled(long requestId, string policyId)`
  - `void MarkBundleFailed(long requestId, string error)`
- Cache identity rules:
  - safe signed product: `product|<normalized signer>|<normalized ProductName>` with stored lowest `MinimumFileVersion`; a newly observed lower version supersedes the cached fragment and queues regeneration.
  - conservative fallback: `hash|<uppercase SHA256>`.

- [ ] **Step 1: Extend the RED test for exact paths and cache identity**

Add assertions:

```python
self.assertIn('BackgroundPolicyQueuePath', paths)
self.assertIn('RuleFragmentDirectory', paths)
self.assertIn('product|', models)
self.assertIn('hash|', models)
self.assertIn('MinimumFileVersion', models)
self.assertIn('Owners', models)
```

- [ ] **Step 2: Run the focused test and verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline.Release0163ApprovalPipelineTests.test_background_queue_is_durable_and_has_required_states -v
```

Expected: FAIL because models/store/paths are absent.

- [ ] **Step 3: Implement the models and paths**

Use `System.Text.Json.Serialization` attributes and explicit status strings. The durable store root is:

```csharp
public static string BackgroundPolicyQueuePath => Path.Combine(ProgramDataRoot, "background-policy-state.json");
public static string RuleFragmentDirectory => Path.Combine(ProgramDataRoot, "RuleFragments");
```

Use these model shapes:

```csharp
public sealed class RuleCacheEntry
{
    public string CacheKey { get; set; } = "";
    public string Kind { get; set; } = "product"; // product | hash
    public string Status { get; set; } = "queued";
    public string? Publisher { get; set; }
    public string? ProductName { get; set; }
    public string? MinimumFileVersion { get; set; }
    public string? Sha256 { get; set; }
    public string RepresentativePath { get; set; } = "";
    public string? FragmentXmlPath { get; set; }
    public int Attempts { get; set; }
    public string? LastError { get; set; }
    public List<string> Owners { get; set; } = [];
    public string UpdatedAt { get; set; } = DateTimeOffset.UtcNow.ToString("O");
}

public sealed class BackgroundBundleMember
{
    public string FilePath { get; set; } = "";
    public string? Publisher { get; set; }
    public string? ProductName { get; set; }
    public string? FileVersion { get; set; }
    public string? Sha256 { get; set; }
    public string RuleKey { get; set; } = "";
}

public sealed class BackgroundBundleJob
{
    public long RequestId { get; set; }
    public long? ScopedPolicyId { get; set; }
    public string ApplicationRoot { get; set; } = "";
    public string Status { get; set; } = "queued";
    public List<string> RequiredRuleKeys { get; set; } = [];
    public List<BackgroundBundleMember> Members { get; set; } = [];
    public string? PolicyId { get; set; }
    public int Attempts { get; set; }
    public string? LastError { get; set; }
    public string UpdatedAt { get; set; } = DateTimeOffset.UtcNow.ToString("O");
}

public sealed class LearningRuleReference
{
    public long? RecordId { get; set; }
    public string FilePath { get; set; } = "";
    public string RuleKey { get; set; } = "";
}

public sealed class BackgroundPolicySnapshot
{
    public List<RuleCacheEntry> Rules { get; set; } = [];
    public List<BackgroundBundleJob> Bundles { get; set; } = [];
    public List<LearningRuleReference> Learning { get; set; } = [];
}
```

- [ ] **Step 4: Implement atomic persistence**

`BackgroundPolicyStore` must use a named global mutex, deserialize under the mutex, mutate in memory, write a UTF-8 no-BOM temp file, and `File.Move(temp, target, true)`. On service start, any `processing` entry left by a crash is returned to `queued` with an incremented attempt counter; do not leave a permanent processing tombstone.

- [ ] **Step 5: Run focused tests**

```bash
python -m unittest server.tests.test_0163_approval_pipeline -v
```

Expected: the durable-store tests pass; later architecture tests remain RED.

- [ ] **Step 6: Commit**

```bash
git add windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs windows-agent/src/AppGuard.Core/Paths.cs windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs server/tests/test_0163_approval_pipeline.py
git commit -m "feat: add durable background policy state"
```

---

### Task 3: Build the one-file foreground primary policy helper

**Files:**
- Create: `windows-agent/scripts/New-PrimaryApprovalPolicy.ps1`
- Modify: `windows-agent/scripts/Common.ps1`
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- Produces PowerShell JSON with the same `SupplementalResult` fields plus `primary_rule_mode`.
- `PolicyHelper.ApproveFilesAsync(...)` continues to be the public command-loop method, but its blocking policy input becomes the selected primary file only.
- `PolicyHelper` retains application-root discovery and returns/queues auxiliary metadata after successful primary install.

- [ ] **Step 1: Add a RED assertion that only one primary path reaches PowerShell**

Add a test that looks for:

```python
self.assertIn('primaryFile', helper)
self.assertIn('files=1', primary_script)
self.assertIn('New-PrimaryApprovalPolicy.ps1', helper)
self.assertNotIn('JsonSerializer.Serialize(files)', foreground_section)
```

- [ ] **Step 2: Run the primary tests and verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline.Release0163ApprovalPipelineTests.test_foreground_approval_uses_primary_policy_builder_not_full_bundle_helper -v
python -m unittest server.tests.test_0163_approval_pipeline.Release0163ApprovalPipelineTests.test_primary_policy_prefers_product_name_filepublisher_for_safe_signed_file -v
```

Expected: FAIL.

- [ ] **Step 3: Implement `New-PrimaryApprovalPolicy.ps1`**

Required flow:

```powershell
param(
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string]$Name,
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state=Read-State
if(!$state.base_policy_id){ throw 'Base policy has not been created.' }

$resolved=Resolve-CIFilePath $FilePath
if(-not (Test-Path -LiteralPath $resolved -PathType Leaf)){ throw "Primary approval file does not exist: $FilePath" }
$meta=Get-FileMetadata $resolved
$timer=[Diagnostics.Stopwatch]::StartNew()
$rules=@()
$mode='hash'
if(-not [string]::IsNullOrWhiteSpace([string]$meta.publisher) -and
   (Test-AppGuardProductFamilyCandidate ([string]$meta.product_name) ([string]$meta.publisher))) {
    try {
        $rules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved
        $mode='product'
    } catch {
        $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved
        $mode='filepublisher'
    }
} else {
    try {
        $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved
        $mode='filepublisher'
    } catch {
        $rules += New-CIPolicyRule -Level Hash -DriverFilePath $resolved
        $mode='hash'
    }
}
$timer.Stop()
Write-Output ("ACM_STAGE primary-rule-generation elapsed={0:F1}s file={1} mode={2} rules={3}" -f $timer.Elapsed.TotalSeconds,$resolved,$mode,$rules.Count)
```

Then create a multiple-policy-format supplemental, set the base policy ID, convert, install with `CiTool.exe --update-policy`, refresh, and emit:

```text
ACM_STAGE primary-policy-install elapsed=<seconds>s policy=<guid>
```

The JSON result must include `policy_id`, `rule_type`, primary metadata, counts of `1`, and `primary_rule_mode`.

- [ ] **Step 4: Refactor `PolicyHelper.ApproveFilesAsync` around primary authorization**

Keep `ExpandProtectedApplicationBundles` for discovery. Select `requested[0]` as the primary because the server preserves session first-seen order and stores the request primary as the first item. Change progress phases to:

```text
discovering
Authorizing primary application...
approved
Primary authorization installed; preparing remaining application components in background.
```

Run `New-PrimaryApprovalPolicy.ps1` with only the primary file. Do not serialize the full expanded list into the foreground helper input.

- [ ] **Step 5: Ensure foreground and future background ConfigCI share one semaphore**

Add to `PolicyHelper`:

```csharp
private readonly SemaphoreSlim _policyGenerationGate = new(1, 1);
private volatile int _foregroundWaiters;
public bool ForegroundPending => Volatile.Read(ref _foregroundWaiters) > 0;
```

Wrap foreground ConfigCI with:

```csharp
Interlocked.Increment(ref _foregroundWaiters);
try
{
    await _policyGenerationGate.WaitAsync(ct);
    try { /* run primary helper */ }
    finally { _policyGenerationGate.Release(); }
}
finally { Interlocked.Decrement(ref _foregroundWaiters); }
```

Expose an internal/background method that acquires the same gate only when `ForegroundPending == false`. This prevents two ConfigCI pipelines from running concurrently.

- [ ] **Step 6: Run tests**

```bash
python -m unittest server.tests.test_0163_approval_pipeline -v
python -m unittest discover -s server/tests -v
```

Expected: primary tests pass; unrelated 0.16.x regressions remain green.

- [ ] **Step 7: Commit**

```bash
git add windows-agent/scripts/New-PrimaryApprovalPolicy.ps1 windows-agent/scripts/Common.ps1 windows-agent/src/AppGuard.Service/PolicyHelper.cs server/tests/test_0163_approval_pipeline.py
git commit -m "feat: authorize primary application before bundle work"
```

---

### Task 4: Turn bundle discovery into safe auxiliary rule-fragment jobs

**Files:**
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Create: `windows-agent/scripts/New-RuleFragment.ps1`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- Produces `QueueBackgroundBundle(long requestId, long? scopedPolicyId, BundleExpansionResult expansion, SupplementalResult primary)`.
- `New-RuleFragment.ps1` accepts `-Kind product|hash`, one `-FilePath`, one output path, and does not install a policy.

- [ ] **Step 1: Write RED tests for same-root/same-signer grouping**

The test should require code that:

```text
- excludes the primary signer+ProductName group from auxiliary work
- groups remaining safe files by normalized signer+ProductName
- turns missing/unsafe ProductName members into SHA256/hash work
- never includes a file whose signer differs from the primary signer
- never queues a path outside the discovered application root
```

Use source assertions for `NormalizePublisher`, `ProductName`, `ApplicationRoot`, and `RuleKey` plus a dedicated pure C# grouping helper if practical.

- [ ] **Step 2: Verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline -v
```

- [ ] **Step 3: Extend bundle discovery metadata without hashing every candidate unnecessarily**

`BundleExpansionResult` should carry `BundleFileIdentity` values:

```csharp
internal sealed record BundleFileIdentity(
    string FilePath,
    string Publisher,
    string? ProductName,
    string? FileVersion,
    string? Sha256);
```

Read `ProductName`/`FileVersion` from `FileVersionInfo`. Compute SHA256 only for files that fall back to hash work; do not hash the full bundle just to group signed ProductName files.

- [ ] **Step 4: Implement safe auxiliary grouping**

For each discovered same-publisher member:

1. Reject it if it is outside the normalized root.
2. Reject it if normalized publisher differs from the primary publisher.
3. If ProductName is safe and matches the primary ProductName, mark it covered by the primary policy; do not queue it.
4. If ProductName is safe but different, upsert one product cache entry for signer+ProductName using the lowest parseable version as the representative.
5. Otherwise compute SHA256 and upsert one hash cache entry per exact file.
6. Queue one `BackgroundBundleJob` containing all required rule keys and the auxiliary component metadata.

Log:

```text
bundle-background queued request=<id> root=<root> discovered=<n> primaryCovered=<n> productGroups=<n> hashFiles=<n> cached=<n> queued=<n>
```

- [ ] **Step 5: Implement `New-RuleFragment.ps1`**

For `-Kind product`:

```powershell
$rules = @(New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved)
```

For `-Kind hash`:

```powershell
$rules = @(New-CIPolicyRule -Level Hash -DriverFilePath $resolved)
```

Create a multiple-policy-format XML with `New-CIPolicy -Rules $rules`, but stop there. Do not set it active, convert it, or call CiTool. Output JSON with `fragment_xml_path`, `rule_count`, `kind`, and elapsed seconds.

- [ ] **Step 6: Run tests and commit**

```bash
python -m unittest discover -s server/tests -v
git add windows-agent/src/AppGuard.Service/PolicyHelper.cs windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs windows-agent/scripts/New-RuleFragment.ps1 server/tests/test_0163_approval_pipeline.py
git commit -m "feat: queue reusable auxiliary rule fragments"
```

---

### Task 5: Add the background worker and one request-specific merged supplemental policy

**Files:**
- Create: `windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs`
- Create: `windows-agent/scripts/Install-MergedSupplemental.ps1`
- Modify: `windows-agent/src/AppGuard.Service/Program.cs`
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `windows-agent/src/AppGuard.Service/ApiClient.cs`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- `BackgroundPolicyProcessor.ProcessOneAsync(CancellationToken)` does at most one fragment generation or one ready-bundle merge/install per call.
- `ApiClient.ReportBackgroundPolicyAsync(BackgroundPolicyReport body, CancellationToken)` posts to `/api/background-policies/report`.

- [ ] **Step 1: Add RED tests for one-at-a-time processing and foreground priority**

Require `RunBackgroundPolicyLoopAsync`, `ProcessOneAsync`, `ForegroundPending`, and a delay between iterations. Assert `Task.WhenAll` includes the new loop.

- [ ] **Step 2: Verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline.Release0163ApprovalPipelineTests.test_background_work_runs_in_a_separate_loop_and_is_serialized_with_foreground -v
```

- [ ] **Step 3: Implement `Install-MergedSupplemental.ps1`**

Inputs:

```powershell
param(
    [Parameter(Mandatory=$true)][string]$FragmentListPath,
    [Parameter(Mandatory=$true)][string]$Name,
    [switch]$Json
)
```

Read a JSON string array of fragment XML paths. Validate all exist. Use the first fragment as leftmost input, merge all fragments to a new XML:

```powershell
Merge-CIPolicy -PolicyPaths ([string[]]$fragments) -OutputFilePath $mergedXml
Set-CIPolicyIdInfo -FilePath $mergedXml -PolicyName $Name -ResetPolicyID | Out-Null
Set-CIPolicyIdInfo -FilePath $mergedXml -SupplementsBasePolicyID ([guid]$state.base_policy_id) | Out-Null
Set-CIPolicyVersion -FilePath $mergedXml -Version '1.0.0.0'
```

Convert/install/refresh, then verify the new GUID is present, enforced, and authorized in `(CiTool.exe -lp -json | ConvertFrom-Json).Policies` before returning success.

Emit:

```text
ACM_STAGE background-policy-merge elapsed=<s>s fragments=<n>
ACM_STAGE background-policy-install elapsed=<s>s policy=<guid>
```

- [ ] **Step 4: Implement `BackgroundPolicyProcessor`**

Algorithm per call:

```text
if PolicyHelper.ForegroundPending: return
if a queued/superseded rule exists:
    claim one rule
    acquire background policy gate
    run New-RuleFragment.ps1
    mark ready or failed
    return
if a queued bundle has all required rules ready:
    claim bundle
    acquire background policy gate
    run Install-MergedSupplemental.ps1 with ready fragment paths
    mark installed
    POST background result to server
    return
```

Retry failures with bounded backoff stored in `Attempts`; do not hot-loop. Initial policy: retry at most 3 times automatically, then leave `failed` for diagnostics/requeue in a later release.

- [ ] **Step 5: Add a fourth AgentWorker loop**

In `ExecuteAsync`:

```csharp
var backgroundPolicyTask = RunBackgroundPolicyLoopAsync(stoppingToken);
await Task.WhenAll(maintenanceTask, commandTask, backgroundPolicyTask, pipeTask);
```

Loop every 5 seconds when work exists, 15 seconds when idle. It must not call heartbeat or command APIs itself.

- [ ] **Step 6: Run tests and commit**

```bash
python -m unittest discover -s server/tests -v
git add windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs windows-agent/scripts/Install-MergedSupplemental.ps1 windows-agent/src/AppGuard.Service/Program.cs windows-agent/src/AppGuard.Service/AgentWorker.cs windows-agent/src/AppGuard.Service/PolicyHelper.cs windows-agent/src/AppGuard.Service/ApiClient.cs windows-agent/src/AppGuard.Core/Models.cs server/tests/test_0163_approval_pipeline.py
git commit -m "feat: process application bundle policy work in background"
```

---

### Task 6: Add server-side background-policy reporting and correct approval inventory semantics

**Files:**
- Modify: `server/app.py`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Modify: `windows-agent/src/AppGuard.Service/ApiClient.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- New agent endpoint: `POST /api/background-policies/report`.
- Request body:

```python
class BackgroundPolicyReport(BaseModel):
    request_id: int
    scoped_policy_id: Optional[int] = None
    status: str
    policy_id: Optional[str] = None
    detail: Optional[str] = None
    components: list[ApprovalComponentIn] = Field(default_factory=list)
```

- Additive table:

```sql
CREATE TABLE IF NOT EXISTS approval_background_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    request_id INTEGER NOT NULL,
    policy_definition_id INTEGER,
    policy_id TEXT,
    status TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(device_id,request_id,policy_id)
);
```

- [ ] **Step 1: Add RED API/schema tests**

Use a temporary DB import of `server.app`, call `init_db()`, inspect `sqlite_master`, and verify no `DROP TABLE`/destructive migration is used.

- [ ] **Step 2: Verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline -v
```

- [ ] **Step 3: Implement additive schema and endpoint**

On `status='installed'`:

1. Validate the request belongs to the authenticated device.
2. Insert/update `approval_background_policies`.
3. Insert one `approved_components` row per reported component using the background `policy_id` and the original approval's `policy_definition_id`/reported scoped policy ID.
4. Do **not** change an already-approved request back to `approving`.
5. Set a human-readable request note such as `Primary authorization installed; background application coverage completed.` only if it does not overwrite an administrator denial/block message.

On `status='failed'`, record the failure but leave the approval request `approved`.

- [ ] **Step 4: Extend heartbeat diagnostics additively**

Add nullable device columns:

```text
background_policy_status TEXT
background_policy_pending INTEGER
background_policy_failed INTEGER
```

Extend heartbeat models on both agent/server. Agent sends queue snapshot counts. Device detail UI shows a small Background Policy Work row when pending/failed is nonzero.

- [ ] **Step 5: Correct approval completion inventory**

Current `approve_session` completion inserts every commanded item into `approved_components`, even though Path B initially authorizes only the primary. Change completion logic so the foreground command inserts only the path actually returned by `CommandComplete.file_path`/primary request row. Auxiliary components enter `approved_components` only when the background report says the merged policy is installed.

- [ ] **Step 6: Run tests and commit**

```bash
python -m unittest discover -s server/tests -v
git add server/app.py windows-agent/src/AppGuard.Core/Models.cs windows-agent/src/AppGuard.Service/ApiClient.cs windows-agent/src/AppGuard.Service/BackgroundPolicyProcessor.cs server/tests/test_0163_approval_pipeline.py
git commit -m "feat: track background approval policy completion"
```

---

### Task 7: Revoke every policy layer linked to an approval safely

**Files:**
- Modify: `server/app.py`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- Produces helper `linked_policy_ids_for_request(conn, device_id, request_id) -> list[str]`.
- Revocation of an approval request/component queues removal of primary and background supplemental IDs associated with that same request.

- [ ] **Step 1: Write RED test for multi-policy revoke**

Create temp DB records with one request, one primary `approved_applications` row, and two `approval_background_policies`/`approved_components` policy IDs. Assert `linked_policy_ids_for_request` returns all unique GUIDs and excludes unrelated request IDs.

- [ ] **Step 2: Verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline.Release0163ApprovalPipelineTests.test_revoke_queues_all_policy_layers_linked_to_same_request -v
```

- [ ] **Step 3: Implement linked policy lookup**

Collect distinct IDs from:

```sql
approved_applications WHERE device_id=? AND request_id=? AND status IN ('approved','revoking')
approved_components   WHERE device_id=? AND request_id=? AND status IN ('approved','blocked','revoking')
approval_background_policies WHERE device_id=? AND request_id=? AND status='installed'
```

Normalize GUIDs to uppercase and discard non-GUID placeholders such as `command-123`.

- [ ] **Step 4: Update component/request/scoped-policy revoke paths**

When a user revokes a component that belongs to an approval request, queue `revoke_approval` commands for every linked policy ID for that request. Existing one-command-at-a-time server dispatch can process the pending commands sequentially. Mark linked rows `revoking`; after each successful removal update only rows carrying that policy ID. The request becomes `revoked` only after no active linked policy IDs remain.

- [ ] **Step 5: Run tests and commit**

```bash
python -m unittest discover -s server/tests -v
git add server/app.py server/tests/test_0163_approval_pipeline.py
git commit -m "fix: revoke all supplemental layers for an approval"
```

---

### Task 8: Queue Learning events into the reusable fragment cache

**Files:**
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Modify: `windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- `AgentWorker.UploadEventsAsync` keeps uploaded `EventUpload` objects long enough to queue learning references after successful server upload.
- Only Event ID `3076` while `PolicyInspector.GetMode() == "learning"` is used for learning precomputation.

- [ ] **Step 1: Add RED test**

Require source markers for `EventId == 3076`, `learning`, `UpsertProductCandidate`, `UpsertHashCandidate`, and dedupe/reuse.

- [ ] **Step 2: Verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline -v
```

- [ ] **Step 3: Implement learning enqueue after successful event upload**

For each uploaded learning event:

```text
safe signed publisher + ProductName + parseable version -> product cache key
otherwise if sha256 present                              -> hash cache key
otherwise                                               -> log unpreparable event; do not pretend ready
```

Add/refresh a `LearningRuleReference` so Enable Enforcement can map the observed learned path to a required cache key. Repeated events for the same cache key do not queue duplicate ConfigCI work.

For a safe product key, if a newly observed version is lower than `MinimumFileVersion`, mark the existing cache entry `superseded`, replace the representative, and queue regeneration. Higher/equal versions reuse the existing lower-minimum fragment.

- [ ] **Step 4: Add diagnostics**

Log no more than once per uploaded chunk:

```text
learning-prep observed=<n> productCandidates=<n> hashCandidates=<n> reused=<n> queued=<n> unpreparable=<n>
```

- [ ] **Step 5: Run tests and commit**

```bash
python -m unittest discover -s server/tests -v
git add windows-agent/src/AppGuard.Service/AgentWorker.cs windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs windows-agent/src/AppGuard.Core/BackgroundPolicyModels.cs server/tests/test_0163_approval_pipeline.py
git commit -m "feat: precompute learned authorization in background"
```

---

### Task 9: Replace the 26-minute enforcement rebuild with fragment merge + final delta

**Files:**
- Create: `windows-agent/scripts/Install-LearnedBaselineFromFragments.ps1`
- Modify: `windows-agent/scripts/End-LearningAndEnforce.ps1`
- Modify: `windows-agent/src/AppGuard.Service/PolicyHelper.cs`
- Modify: `windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- `PolicyHelper.EnableEnforcementAsync` obtains/updates the final learned snapshot, asks `BackgroundPolicyStore` for required keys, synchronously finishes only unprepared delta keys through the same serialized fragment generator, then calls the learned merge installer.
- `Install-LearnedBaselineFromFragments.ps1` accepts a JSON list of fragment XML paths and installs one current learned baseline.

- [ ] **Step 1: Write RED tests for delta-only behavior and safe cleanup ordering**

Require markers:

```text
ACM_STAGE learned-final-delta
prepared=
unprepared=
ACM_STAGE learned-baseline-merge
ACM_STAGE learned-baseline-install
stale learned-baseline policies removed
```

And assert `New-LearnedBaselinePolicy.ps1` is not invoked by `End-LearningAndEnforce.ps1`.

- [ ] **Step 2: Verify RED**

```bash
python -m unittest server.tests.test_0163_approval_pipeline.Release0163ApprovalPipelineTests.test_learning_enforcement_consumes_prepared_fragments_and_only_generates_delta -v
```

- [ ] **Step 3: Implement final delta preparation**

Keep `Get-LearnedApplications.ps1 -Save` because the measured full event snapshot is only ~8 seconds and is useful as a correctness reconciliation. Convert each learned item to the same stable cache key used during incremental Learning. For any required key not `ready`, run the fragment generator synchronously one item at a time and fail explicitly if it still cannot become ready.

Emit:

```text
ACM_STAGE learned-final-delta elapsed=<s>s learned=<n> prepared=<n> unprepared=<n>
```

- [ ] **Step 4: Implement `Install-LearnedBaselineFromFragments.ps1`**

1. Validate all fragment paths.
2. `Merge-CIPolicy` them to a new XML.
3. Reset policy ID/name to exactly `AppControl Manager Learned Baseline` and set the current base policy ID.
4. Convert to CIP and install.
5. Verify new policy is present/enforced/authorized with `CiTool.exe -lp -json`.
6. Only **after** verification, enumerate other policies whose friendly name is exactly `AppControl Manager Learned Baseline` and whose policy ID is not the new ID.
7. Remove each stale policy with `CiTool.exe --remove-policy "{GUID}" -json`; log failures but do not uninstall the newly successful replacement.
8. Refresh and output the new GUID.

Emit:

```text
ACM_STAGE learned-baseline-merge elapsed=<s>s fragments=<n>
ACM_STAGE learned-baseline-install elapsed=<s>s policy=<guid>
ACM_STAGE learned-baseline-cleanup elapsed=<s>s removed=<n> failed=<n>
```

- [ ] **Step 5: Keep the base enforcement flip last**

Only after learned baseline install succeeds should the existing base XML remove audit mode and increment policy version. Preserve `Disabled:Script Enforcement` as in 0.16.2.

- [ ] **Step 6: Run tests and commit**

```bash
python -m unittest discover -s server/tests -v
git add windows-agent/scripts/Install-LearnedBaselineFromFragments.ps1 windows-agent/scripts/End-LearningAndEnforce.ps1 windows-agent/src/AppGuard.Service/PolicyHelper.cs windows-agent/src/AppGuard.Service/BackgroundPolicyStore.cs server/tests/test_0163_approval_pipeline.py
git commit -m "feat: enable enforcement from prepared learned fragments"
```

---

### Task 10: Add user-visible primary/background states without making background failure revoke approval

**Files:**
- Modify: `server/app.py`
- Modify: `windows-agent/src/AppGuard.Service/PolicyProgressTracker.cs`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Test: `server/tests/test_0163_approval_pipeline.py`

**Interfaces:**
- Request remains `approved` after primary command completion.
- Background status comes from `approval_background_policies`, not from changing request back to an in-progress/failed approval state.

- [ ] **Step 1: Add RED tests**

Require request UI labels/messages for:

```text
Authorizing primary
Approved — background application coverage is still processing
Bundle ready
Background coverage failed; primary approval remains installed
```

- [ ] **Step 2: Implement status mapping**

Keep existing request status vocabulary for compatibility. Add a derived helper:

```python
def request_background_status(conn, request_id):
    ...
```

Display background state on request detail/history and device diagnostics. Do not change the base request status away from `approved` because of background failure.

- [ ] **Step 3: Progress tracker phases**

Foreground phases:

```text
discovering
authorizing_primary
approved
```

Background activity is heartbeat/server diagnostics, not a foreground tray wait state.

- [ ] **Step 4: Run tests and commit**

```bash
python -m unittest discover -s server/tests -v
git add server/app.py windows-agent/src/AppGuard.Service/PolicyProgressTracker.cs windows-agent/src/AppGuard.Core/Models.cs server/tests/test_0163_approval_pipeline.py
git commit -m "feat: show background bundle completion separately"
```

---

### Task 11: Version 0.16.3, document rollback, and run release verification

**Files:**
- Modify: `server/app.py`
- Modify: `server/upgrade-server.sh`
- Modify: `server/tests/test_version_surfaces.py`
- Modify: `.github/workflows/build-windows.yml`
- Modify: `windows-agent/Build.ps1`
- Modify: `windows-agent/src/AppGuard.Service/AppGuard.Service.csproj`
- Modify: `windows-agent/src/AppGuard.Tray/AppGuard.Tray.csproj`
- Modify: `windows-agent/src/AppControlManager.Installer/AppControlManager.Installer.csproj`
- Modify: `windows-agent/src/AppGuard.Service/AgentWorker.cs`
- Modify: `windows-agent/src/AppGuard.Core/Models.cs`
- Modify: `windows-agent/src/AppControlManager.Installer/Program.cs`
- Modify: `windows-agent/Install-Agent.ps1`
- Modify: `windows-agent/Upgrade-Agent.ps1`
- Modify: `README.md`
- Create: `0.16.3-FEATURES.txt`
- Test: all server tests and packaging checks.

**Interfaces:**
- Release version is exactly `0.16.3` across server/agent/workflows.
- `0.16.3-FEATURES.txt` explicitly identifies 0.16.2 as rollback/reference baseline.

- [ ] **Step 1: Change version-surface test to 0.16.3 and add release-note expectations**

Set:

```python
VERSION = "0.16.3"
```

Require feature-note phrases:

```text
primary approval
background bundle
learning precomputation
0.16.2
rollback
```

- [ ] **Step 2: Run version test and verify RED**

```bash
python -m unittest server.tests.test_version_surfaces -v
```

Expected: FAIL until production version strings change.

- [ ] **Step 3: Update every version surface and release notes**

Preserve the 0.16.2 source artifact externally; do not rename/delete it from Library. Release notes must state that 0.16.3 changes approval architecture and that 0.16.2 is the rollback/reference baseline if the background approach proves unsuitable.

- [ ] **Step 4: Run full verification**

```bash
python -m unittest discover -s server/tests -v
python -m py_compile server/app.py server/release_management.py server/import-agent-release.py
bash -n server/install-server.sh server/upgrade-server.sh server/update-from-github.sh
python - <<'PY'
from pathlib import Path
import yaml
for p in Path('.github/workflows').glob('*.yml'):
    yaml.safe_load(p.read_text())
    print('YAML OK', p)
PY
git diff --check
```

Also verify shell line endings:

```bash
python - <<'PY'
from pathlib import Path
bad=[]
for p in Path('.').rglob('*.sh'):
    if b'\r\n' in p.read_bytes(): bad.append(str(p))
if bad: raise SystemExit('CRLF shell files: ' + ', '.join(bad))
print('All .sh files are LF-only')
PY
```

- [ ] **Step 5: Do not claim Windows runtime success from Linux**

Document that the Linux environment cannot execute Windows ConfigCI or compile/sign the Windows artifacts if `dotnet` is unavailable. The GitHub Actions release must build and Artifact Sign the Service, Tray, and Installer, and the endpoint test must validate actual WDAC behavior.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Release AppControl Manager 0.16.3"
```

---

## Endpoint Acceptance Test After GitHub Release

Do not treat unit/source tests as proof of the Windows behavior. On the existing test endpoint, validate in this order:

1. Confirm Service and Tray are `0.16.3.0` and Authenticode `Valid`.
2. Return device to Learning and leave it long enough to observe several applications; verify heartbeats remain online while background rule-fragment jobs run.
3. Check agent log for `learning-prep` and background rule timing; repeated signer/ProductName observations must show reuse rather than duplicate ConfigCI work.
4. Enable Enforcement. Capture `learned-final-delta`, `learned-baseline-merge`, `learned-baseline-install`, and cleanup timings. Confirm only one current `AppControl Manager Learned Baseline` remains active.
5. Block/revoke Chrome authorization as needed, create a fresh Chrome request, approve once, and measure time to application launch. Target blocking path: one primary ConfigCI operation (measured historical reference ~35 seconds) plus ~1–2 seconds policy install, not ~13 minutes.
6. While Chrome auxiliary work continues, verify the request is `approved`, the device is Online, and background status moves processing → installed or failed independently.
7. Revoke the Chrome approval. Confirm all primary/background policy IDs linked to the request are queued for removal and that no AppControl Manager-generated background Chrome policy remains active afterward.
8. If authorization correctness, background churn, or revocation semantics are unacceptable, stop 0.16.3 rollout and return development to the retained 0.16.2 source baseline rather than layering a fourth architecture change on top.
