# AppControl Manager 0.16.3 Approval Pipeline Design

## Purpose

AppControl Manager 0.16.3 changes the approval and learning architecture so user-facing operations no longer wait for ConfigCI to analyze every executable and DLL in an application bundle. Version 0.16.2 is the explicit rollback/reference baseline for this work.

## Evidence driving the change

Testing on the Windows endpoint established that AppControl Manager discovery, deduplication, policy conversion, and CiTool installation are fast, while `New-CIPolicyRule` can be extremely slow for some third-party signed binaries.

Measured examples:

- Chrome bundle discovery: about 6.6 seconds for 22 Google-signed policy inputs.
- Chrome bundle rule generation: about 781.6 seconds for 22 inputs.
- `chrome.exe` alone: about 35 seconds whether generating FilePublisher/ProductName or Hash rules.
- Learned baseline collection/deduplication/classification: about 8.4 seconds total for 191 learned records / 186 unique files.
- Learned baseline family rule generation: about 1425.9 seconds for 43 ProductName representatives.
- XML creation, CIP conversion, installation, and enforcement switch: roughly 2 seconds total once rules exist.

The bottleneck is therefore ConfigCI analysis of selected binaries, not AppControl Manager file discovery or policy deployment.

## Architecture

### 1. Fast primary approval

For a signed application approval, AppControl Manager identifies the primary executable and its signer, ProductName, version information, and application root. The blocking approval path generates the minimum durable rule required to authorize the requested application, preferring one ProductName-scoped FilePublisher rule generated from the primary executable.

The approval completes after that primary rule is installed. It does not wait for ConfigCI to process every same-publisher executable or DLL discovered under the application root.

For applications without safe FilePublisher metadata, the existing conservative fallback behavior remains available.

### 2. Background bundle completion

Application discovery remains useful, but discovered auxiliary files become background work rather than blocking approval.

After the primary rule is installed, AppControl Manager queues auxiliary application families/components for background policy generation. Background work is constrained to the approved application root and expected signer(s); approval of one application never becomes publisher-wide authorization.

Files are grouped by signer + ProductName where safe. Files with missing or unsuitable product metadata are handled conservatively. Existing policies and cached generated rules are reused where possible.

The agent continues heartbeats, event uploads, and command polling while background policy work is running.

### 3. Learning mode precomputation

Learning mode incrementally stages learned application authorization instead of postponing all expensive ConfigCI work until `Enable Enforcement`.

As new learned applications are observed, AppControl Manager records their metadata and queues primary/product rule generation in the background. Repeated observations of an already prepared signer/ProductName combination do not trigger duplicate ConfigCI work.

When `Enable Enforcement` is selected, the agent processes only a small unprepared delta, installs/reuses the staged learned baseline, and switches the base policy from audit/learning to enforced mode.

The design does not require the final enforcement operation to be instantaneous if a new delta exists, but the normal case should not rebuild the full history accumulated during Learning.

### 4. Rule cache and identity

Generated authorization work needs a stable cache identity based on the attributes that make a rule reusable. For the first implementation, signed ProductName rules are keyed by normalized signer identity + ProductName + relevant version boundary. Hash/file fallback entries use the necessary file identity/hash metadata.

The cache records whether a rule is queued, processing, ready, installed, superseded, or failed. Failed background generation can retry without blocking device heartbeats or unrelated commands.

### 5. Learned baseline lifecycle

Only the currently intended AppControl Manager learned baseline should remain active for the base policy. When a replacement learned baseline is installed successfully, obsolete AppControl Manager learned-baseline supplemental policies are removed.

Removal occurs only after the replacement is confirmed installed/authorized. Failure to remove an obsolete policy is logged and retried rather than causing the successful new baseline to be discarded.

### 6. Safety boundaries

This release does not introduce publisher-wide trust.

- ProductName rules remain scoped to the signer and product metadata produced by ConfigCI.
- Auxiliary background work is limited to the approved application root and expected signer relationship discovered during approval.
- Microsoft-signed or otherwise already-authorized components are not redundantly added when the existing active policy already permits them.
- Missing metadata never silently broadens authorization.
- The reusable enrollment-token model is unchanged.

### 7. User-visible operation states

Approvals should distinguish the primary authorization from background completion. Suggested internal states are:

- `discovering`
- `authorizing_primary`
- `approved`
- `background_bundle_processing`
- `bundle_ready`
- `background_failed`

A user should be able to launch the approved application once the primary authorization reaches `approved`; bundle completion is not part of the blocking UI wait.

Learning-to-Enforcement progress should distinguish:

- collecting final delta
- preparing final delta
- installing learned baseline
- enabling enforcement

### 8. Timing and diagnostics

Keep existing `ACM_STAGE` timing and add enough detail to separate primary authorization from background completion. At minimum log:

- primary file
- signer/product identity
- primary rule generation seconds
- discovered auxiliary file count
- auxiliary groups queued
- cached/reused groups
- background rule generation seconds per group
- final policy install seconds
- learned delta count at enforcement
- prepared vs unprepared learned groups
- stale learned-baseline policies removed

### 9. Server timestamp configuration

0.16.3 also adds a server display-timezone setting because it is independent of WDAC policy semantics but affects current product usability.

- Store internal timestamps in UTC.
- Add a Settings timezone using an IANA timezone identifier (for example `America/Chicago`).
- Convert timestamps only when rendering UI/API presentation intended for humans.
- Use a concise local display such as `Aug 27, 2026 7:04 PM` for full timestamps and a shorter equivalent where space is constrained.
- Apply consistently to devices, last-seen values, approvals, activity/history, commands, updates, enrollment events, and other visible timestamps.
- Daylight-saving changes follow the configured IANA timezone automatically.

### 10. Rollback strategy

Version 0.16.2 is the explicit known-good rollback/reference baseline for the pre-background architecture.

If 0.16.3 causes authorization correctness problems, excessive background churn, or regressions that cannot be resolved safely, development can return to the retained 0.16.2 source and pursue an alternate architecture. The 0.16.3 update must not intentionally create a database migration that prevents the 0.16.2 server code from reading existing core data. New state needed for background processing should be additive and disposable where practical.

A client rollback still must account for WDAC policies already installed on the endpoint; rollback logic must not assume replacing the binary alone reverts active Windows policies.

## Error handling

Primary approval failure remains a real approval failure and must be surfaced to the server. Background auxiliary failure does not revoke an already successful primary authorization; it is logged and retried, with status visible for diagnostics.

Learning background failures remain visible but do not mark the device offline. Enable Enforcement must detect unresolved/unprepared learned work and either process the final delta or fail explicitly; it must never silently enable enforcement while known learned authorization is missing.

## Testing

Regression tests must cover:

1. Signed approval uses only the primary representative in the blocking rule-generation call.
2. Auxiliary same-root/same-signer files are queued for background processing rather than included in the blocking call.
3. Already cached signer/ProductName groups are reused without duplicate ConfigCI generation.
4. Missing/unsafe ProductName metadata follows conservative fallback behavior.
5. A background failure does not change a successful primary approval to failed.
6. Heartbeats continue during primary and background policy generation.
7. Learning observations queue incremental preparation and deduplicate repeated groups.
8. Enable Enforcement processes only unprepared delta work before switching mode.
9. Replacement learned baseline removes obsolete AppControl Manager learned baselines only after successful replacement installation.
10. Timezone setting preserves UTC storage and renders configured local time, including DST-aware IANA conversion.
11. 0.16.2 behavior remains the rollback/reference definition and no destructive schema change is introduced solely for background processing.

## Success criteria

On the current Chrome test case, the approval path should stop waiting for all 22 Google-signed files. The expected blocking cost is approximately one ConfigCI primary-rule operation plus policy installation, based on the measured ~35-second `chrome.exe` rule generation rather than the previous ~13-minute bundle operation.

Learning-to-Enforcement should no longer rebuild the full historical learned set during the button click when that work has already been prepared in the background.

Correct authorization remains more important than raw speed. Any optimization that broadens trust beyond the approved signer/product/application boundary is rejected.
