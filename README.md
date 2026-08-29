# AppControl Manager 0.18.1

## 0.18.1 Learning Noise Cleanup

Version 0.18.1 preserves Code Integrity audit inputs immediately so short-lived installer files can still produce safe FilePublisher or hash rules after their original TEMP path disappears. Missing representatives that cannot be preserved now become neutral `expired` work instead of permanent production failures, including migration of the exact legacy 0.18.0 error.

Enforcement remains fail-closed: AppControl Manager does not add TEMP wildcard authorization or weaken WDAC writable-path protection. Unknown and unsigned transient executables remain blocked. The tray only deduplicates repeated UI for the same blocked identity and groups related components for longer; all Code Integrity events continue to reach central telemetry.

## 0.18.0 Consolidated Reliability Release

Version 0.18.0 repairs automatic GitHub Release creation, routes foreground allow and deny generation through the constrained Local Service Rule Worker, adds administrator retry and bounded diagnostics for failed background policy work, removes only stale failed or abandoned worker jobs, and narrowly classifies expected `.NET` single-file extraction children during learning. LocalSystem remains the only process allowed to post-process, convert, install, remove, refresh, or verify WDAC policies.

The `.NET` classifier is deliberately fail-closed: it recognizes only `.net\<application>\<bundle-id>\<child>` below a user's `AppData\Local\Temp` or `Windows\Temp`. It does not ignore arbitrary temporary, NSIS, MSI, traversal, or other similarly named paths. Recognized extraction files are reported separately and do not create warnings, but a non-empty learning session with no usable safe authorization rule still fails.

The required rollout proof is one managed endpoint upgrade from 0.17.2 to 0.18.0, followed by signed-binary and service checks plus foreground allow/deny, Installation Mode, retry, heartbeat, and Enforcement-restoration tests. Retain the published 0.17.2 source and signed assets for immediate rollback; 0.16.2 remains the older architectural reference.

## 0.17.2 Installation Mode Learning Repair

Version 0.17.2 fixes an all-or-nothing Installation Mode finalization path. Valid learned authorization rules are now installed even when temporary or deleted installer files cannot be converted into safe candidates. Mixed results return the endpoint to Enforcement and appear as **Completed With Warnings** with processed, installed, and skipped counts. Sessions with learned activity but no usable authorization rules still fail safely.

Pending installation requests now also appear on the main dashboard in the combined **Pending Requests** queue, including their duration, approval, and denial controls.


## 0.17.1 Managed Update Repair

Version 0.17.1 fixes the Windows PowerShell 5.1 argument parsing failure that returned `sc.exe` exit code 1639 while configuring the Rule Worker during managed updates. The manifest-verified helper now runs directly from the staged update package, and the signed main service owns Rule Worker provisioning through its existing C# implementation. Update activation requires a complete rollback backup, verifies both services, and reports Windows service state and exit codes when startup fails.

Endpoints on 0.16.5 or 0.17.0 need the signed 0.17.1 installer once because their installed activation helper contains the failure. The installer preserves enrollment, policy, learning, and audit data under `C:\ProgramData\AppControlManager`; its protected staging area validates manifest hashes and Authenticode before replacement. Subsequent managed releases can use the staged helper and repair their own activation behavior.

## 0.17.0 Installation Mode

Version 0.17.0 adds administrator-controlled timed **Installation Mode** for software installers that legitimately execute many helper EXEs, DLLs, services, and updater components. A blocked endpoint user can choose **Request Installation** instead of repeatedly requesting each component. The administrator approves a duration, but the endpoint remains in Enforcement until the user clicks **Start Installation**. Approved user requests expire after four hours if they are never started.

Once started, the endpoint enters a locally timed Learning/Audit window (15 minutes by default; 1-240 minutes supported). The 0.16.5 Local Service rule worker continues preparing ConfigCI fragments during the window. On completion, AppControl Manager installs only the newly learned delta as an additional supplemental policy, preserves the existing learned baseline, and returns the base policy to Enforcement. If delta finalization fails, the agent still attempts a force-Enforcement fallback so a failed installer-learning operation cannot leave the endpoint permissive indefinitely. Administrators can also start or end Installation Mode directly from the device page.

## 0.16.5 Local Service ConfigCI rule worker

Version 0.16.5 moves Path B background and learned rule-fragment generation out of the LocalSystem agent process and into a dedicated **AppControl Manager Rule Worker** Windows service running as `NT AUTHORITY\LocalService`. Endpoint diagnostics showed that the same Chrome ProductName `New-CIPolicyRule` call succeeds for an elevated administrator and Local Service but fails under LocalSystem with `An item with the same key has already been added.` The main agent remains LocalSystem and is still the only component that merges, installs, removes, or verifies WDAC policies.

The worker reuses the existing signed `AppControlManager.Service.exe` with `--rule-worker`, consumes tightly constrained jobs under `C:\ProgramData\AppControlManager\RuleWorker`, and generates XML fragments only. The main service stages a copy of each representative file so Local Service does not need broad access to user/application directories. No additional signed executable is introduced.

This release intentionally does not change temporary `.net` learned-file classification, foreground primary approval/deny generation, or the server Enable Enforcement redirect; those are separate follow-ups. **AppControl Manager 0.16.2 remains the rollback/reference baseline for the Path B architecture.**

## 0.16.4 ConfigCI rule-fragment binding fix

Version 0.16.4 is a bounded reliability fix for the 0.16.3 Path B architecture. `New-RuleFragment.ps1` now flattens the rule collection returned by `New-CIPolicyRule` before passing it to `New-CIPolicy -Rules`, preventing the `Microsoft.SecureBoot.UserConfig.Rule` ParameterBindingException seen during learning precomputation and background bundle generation. The primary approval, background bundle, and learning precomputation architecture is otherwise unchanged.

## 0.16.3 fast-primary approval and background coverage milestone

Version 0.16.3 changes the approval architecture so a foreground approval installs one primary ProductName-scoped FilePublisher authorization first, then prepares and installs remaining same-root/same-signer application coverage as serialized background work. Learning mode uses the same reusable rule-fragment cache for learning precomputation, and Enable Enforcement consumes prepared fragments plus only the final unprepared delta instead of rebuilding the entire learned history. Primary approvals remain approved if background bundle coverage fails, and revocation removes all AppControl Manager policy layers linked to the request.

The server also adds a global **Settings → Display timezone** option using IANA timezone identifiers. Database and agent/API timestamps remain UTC, while human-facing server timestamps are rendered cleanly in the configured DST-aware timezone.

**Rollback/reference baseline:** retain AppControl Manager **0.16.2** as the known rollback baseline for this architecture branch. If the 0.16.3/0.16.4 primary approval/background bundle model performs poorly or produces unacceptable authorization/revocation behavior, stop rollout and return development to the retained 0.16.2 source rather than layering more architectural changes on top.

## 0.16.2 learned-baseline rule-generation optimization

Version 0.16.2 targets the ConfigCI bottleneck isolated during the 0.16.1 enforcement test. The agent reuses the signer/product/version metadata captured during Learning, groups safe signed files by publisher and product, and sends one lowest-version representative per application family to ProductName-scoped FilePublisher generation. Generic or metadata-poor signed files remain conservative per-file FilePublisher rules, while unsigned files use hash rules. Separate classification, family, individual, hash, XML, conversion, install and total timing markers make the remaining WDAC cost visible. The release also filters quoted ConfigCI `Scan completed successfully` noise from both stdout and stderr, including cancelled or failed policy operations.

The independent heartbeat/command loops introduced in 0.16.1 are retained, so long policy work does not make a healthy endpoint appear Offline. The server version is advanced to 0.16.2 so the GitHub server updater can automatically import the matching 0.16.2 managed-agent release.

## 0.16.0 approval-performance and upgrade-compatibility milestone

Version 0.16.0 combines the 0.15.1 compatibility fixes with the first WDAC approval-performance pass. It fixes Windows PowerShell 5.1 file-list parsing, protects Linux release scripts from CRLF packaging, deduplicates repeated application-root scans, adds an in-memory signer cache keyed by file path/size/modified time, and adds bundle-discovery timing metrics and clearer approval progress.

## 0.15.0 integrated production-management milestone

Version 0.15.0 combines the planned 0.13.x through 0.15.x work into one feature release. It adds a signed GitHub release pipeline, browser-based server update management, automatic import of the matching managed-agent package after a server upgrade, and builds on the existing central application-policy engine with device, group, organization and global scopes. Long-lived reusable enrollment tokens remain unchanged.

### GitHub release signing

Tagged GitHub Releases are intentionally fail-closed: the Service and Tray executables are built first, signed with Azure Artifact Signing, verified, then packaged into the managed-agent ZIP. The installer is built from that signed payload, signed separately, verified, and only then published with fresh SHA256 files. Ordinary `build-windows.yml` CI artifacts remain unsigned development builds.

Configure these GitHub Actions secrets in the `release` environment before creating a signed release tag such as `v0.18.1`:

```text
AZURE_CLIENT_ID
AZURE_TENANT_ID
AZURE_SUBSCRIPTION_ID
AZURE_ARTIFACT_SIGNING_ENDPOINT
AZURE_ARTIFACT_SIGNING_ACCOUNT
AZURE_ARTIFACT_SIGNING_PROFILE
```

The Azure identity used by GitHub OIDC must be authorized to sign with the selected Artifact Signing certificate profile. If signing or signature verification fails, the release workflow stops before `gh release create`.

### Server Updates

Global administrators now have **Administration → Server Updates**. The page shows the installed server version, the latest GitHub Release, the six required source/agent/installer assets, release notes, matching-agent import state, and recent updater output. Installing a server update remains an explicit administrator action.

After a successful server upgrade, `update-from-github.sh` verifies the source ZIP, managed-agent ZIP and installer SHA256 files and automatically imports the matching stable agent release into AppControl Manager. Existing deployment targeting can then roll that release out by device, device group, organization or global scope with rollout percentage controls.

### Application policy scopes

Application approvals and explicit blocks can create durable central policies for **this device**, the device's **group**, the **entire organization**, or **all organizations** (global administrators only). Signed applications prefer publisher/product identities so durable policies can cover application updates without relying only on one executable hash. BLOCK policies take precedence over ALLOW policies.


## 0.13.0 large-bundle approval fix

0.13.0 fixes large protected-application approvals that could exceed the Windows process command-line limit when hundreds of component paths were passed to `powershell.exe -Command`. The agent service now writes the expanded component list to a temporary JSON data file and passes only that short filename to the existing policy helper, preserving bundle coverage without the command-line-size failure. See `0.13.0-FIXES.txt`.

AppControl Manager 0.13.0 is a maintenance release built on the validated 0.12.5 usability baseline. It preserves the long-lived reusable enrollment-token and tray-menu behavior from 0.12.5 while fixing large application-bundle approvals.

## Long-lived reusable enrollment tokens

Enrollment tokens remain valid until an administrator disables them. This is intentional so a token can be embedded in RMM/onboarding automation such as VSA X workflows.

Beginning with 0.12.5, newly created enrollment tokens are retained in the server database in addition to their authentication hash. Administrators with access to the organization can therefore copy the token again later from **Organizations → Enrollment Tokens**.

The token creation screen and Organizations screen provide **Copy** buttons. The creation screen also provides a Copy button for the silent installer command.

Tokens created by earlier releases were stored only as hashes and cannot be reconstructed. They continue to work, but the console can show only their prefix. Create a new token if you want it to be retrievable/copyable from the server.

## Windows tray menu

The tray menu is now:

```text
Request application approval...
Request History...
Learning / Enforced / Offline / Unknown
------------------------------
Exit
```

The status line is informational and no longer opens a separate status popup. `Offline` is shown when the tray cannot successfully communicate with the AppControl Manager server through the local service. Otherwise the current WDAC mode is displayed as `Learning` or `Enforced`; `Unknown` is used while local policy state cannot be determined.

The Request History window retains recent and completed requests and is the renamed version of the previous Current Requests window.

## Windows agent version

The Windows agent version is 0.13.0 because this release changes the agent service and its supplemental-policy helper. The resulting WDAC allow rules and application-bundle coverage are unchanged; only the transport of the expanded file list into PowerShell is different.

## Upgrade server

```bash
cd AppControlManager-0.13.0/server
sudo ./upgrade-server.sh
```

Verify:

```bash
curl http://127.0.0.1:8090/health
```

Expected:

```json
{"ok":true,"version":"0.13.0"}
```

## Build Windows agent

The included GitHub Actions workflow builds the self-contained Windows x64 agent/update ZIP and single-file installer using .NET 10. You can also build on Windows with:

```powershell
.\Build.ps1 -Version 0.13.0
```

## 0.13.0 command hardening

Version 0.13.0 adds server command validation, per-dispatch command claims, stale-completion rejection, local successful-command receipts for replay suppression, and command attempt counts. Long-lived reusable enrollment tokens are intentionally unchanged.

## 0.13.1 GitHub release integration

The AppControl Manager server can now pull server releases directly from GitHub Releases:

```bash
sudo /opt/appcontrol-manager/update-from-github.sh --check
sudo /opt/appcontrol-manager/update-from-github.sh --install
```

The default repository is `flattery103/AppControlManager`. Override it with `APPCONTROL_GITHUB_REPO=owner/repo` if needed. Public repositories need no GitHub credential. If the repository is later private, define `APPCONTROL_GITHUB_TOKEN` in the environment used to invoke the updater.

Pushing a version tag such as `v0.13.1` triggers `.github/workflows/release.yml`. GitHub Actions builds and publishes the source ZIP/checksum, Windows managed-agent ZIP/checksum, and Windows installer/checksum as GitHub Release assets.
