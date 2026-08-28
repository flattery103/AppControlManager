# AppControl Manager 0.16.5 Local Service Rule Worker Design

## Problem

AppControl Manager 0.16.4 fixed a PowerShell rule-array binding bug, but endpoint testing exposed a separate Windows ConfigCI execution-context defect. The exact Chrome ProductName `New-CIPolicyRule` call succeeds for an elevated administrator and for `NT AUTHORITY\LOCAL SERVICE`, but fails for `NT AUTHORITY\SYSTEM` with `System.ArgumentException: An item with the same key has already been added.` The main AppControl Manager agent intentionally runs as LocalSystem because policy installation and endpoint-control operations require that privilege.

The 0.16.5 change must therefore separate generation-only ConfigCI work from privileged policy installation without weakening the main service or depending on an interactive user.

## Scope

0.16.5 changes only the Path B background/learned rule-fragment generation boundary. It does not redesign foreground approval policy generation, deny-policy generation, temporary `.net` learning classification, or the server-side Enable Enforcement redirect. Those remain separate follow-up work.

0.16.2 remains the architectural rollback/reference baseline.

## Architecture

The existing signed `AppControlManager.Service.exe` will be registered twice:

- `AppControlManager` runs normally as LocalSystem and keeps all server communication, command processing, policy merge/install/remove, updater, state, and privileged operations.
- `AppControlManagerRuleWorker` runs the same executable with `--rule-worker` as `NT AUTHORITY\LOCAL SERVICE`. In this mode the executable starts only a narrow rule-worker hosted service and does not instantiate API, enrollment, command, updater, tray, or policy-install components.

Using the same signed executable avoids adding another binary/signing artifact while still creating a distinct Windows service security context and code path.

## File-Based Job Boundary

Communication uses a locked-down file queue under:

`C:\ProgramData\AppControlManager\RuleWorker\Jobs`

The RuleWorker root disables inherited permissions and grants only:

- `SYSTEM`: Full Control
- `BUILTIN\Administrators`: Full Control
- `LOCAL SERVICE`: Modify

For each generation request, the SYSTEM service creates a GUID-named job directory, copies the representative file into that directory using its original extension, then atomically publishes `request.json`. The request contains only a job ID, rule kind (`product` or `hash`), and the staged input filename. It cannot specify an arbitrary script or arbitrary output location.

The Local Service worker processes jobs sequentially. It validates that the job ID matches the directory, the rule kind is allowlisted, and the input filename is a basename inside that job directory. It invokes the fixed `New-RuleFragment.ps1` script and always writes to that job's fixed `fragment.xml`. It atomically writes `result.json` containing success/failure, rule count, kind, elapsed time, and sanitized error text.

The SYSTEM service waits for `result.json`. On success it verifies the fragment exists inside the expected job directory and that at least one rule was generated, then copies the fragment into the existing canonical `RuleFragments` cache path. The transient job directory is removed after successful consumption. Failed/cancelled jobs may remain for later cleanup/diagnostics but are never treated as ready fragments.

## PowerShell Privilege Boundary

`New-RuleFragment.ps1` is generation-only: it resolves a file, calls ConfigCI `New-CIPolicyRule`/`New-CIPolicy`, and writes XML. It does not call `CiTool`, change WDAC state, or install a policy. Therefore its `Assert-Administrator` call will be removed so Local Service can execute it.

All scripts that install, remove, convert/install, or otherwise modify WDAC policy state retain administrator checks and continue running only from the LocalSystem main service.

## Installation and Update Lifecycle

First install, manual upgrade, and managed self-update must all:

1. Create/secure the RuleWorker directory.
2. Register `AppControlManagerRuleWorker` with binary path `"C:\Program Files\AppControlManager\AppControlManager.Service.exe" --rule-worker`, startup type Automatic, and account `NT AUTHORITY\LocalService`.
3. Start the Rule Worker before or alongside the main service.

Managed self-update must stop both services before replacing the shared executable and restart both afterward. Rollback must likewise restore and restart both services. Uninstall removes both service registrations while retaining ProgramData/policies as the current uninstall behavior does.

## Security Constraints

- The Local Service worker gets no server URL/device key through dependency injection and does not read `config.json` as part of its code path.
- It cannot request arbitrary scripts, output paths, or policy installation.
- SYSTEM stages a copy of the target file, so Local Service does not need broad read access to user profile or application directories.
- Job input/output paths are constrained to a GUID job directory beneath the configured RuleWorker root.
- The SYSTEM service remains the sole policy installer/merger/remover.
- No interactive logged-in user is required.

## Observability and Failure Behavior

The worker writes `rule-worker.log` in the secured RuleWorker directory. Main-service logs retain `background-rule-fragment` timing/output semantics and add worker job start/completion/failure context.

If the worker is unavailable, a job times out/cancels, or generation fails, the existing background/final-delta flow marks the rule failed. Enable Enforcement remains fail-closed: it stays in Learning mode when required fragments remain unresolved.

## Release and Test Requirements

0.16.5 must add regression tests that prove:

- `New-RuleFragment.ps1` is generation-only and no longer asserts administrator privilege.
- Program startup has a dedicated `--rule-worker` Local Service mode with no normal agent registrations in that branch.
- rule-worker requests accept only `product`/`hash`, fixed staged inputs, and fixed fragment output.
- `PolicyHelper` routes background/learned fragment generation through the worker client instead of direct SYSTEM PowerShell.
- install/update/uninstall lifecycle creates, stops, starts, and removes the Rule Worker appropriately.
- build/release/version surfaces move to 0.16.5 without adding a new signing artifact.

Windows runtime confirmation after deployment must re-run the Chrome ProductName fragment path through AppControl Manager and then Enable Enforcement. GitHub Actions remains authoritative for .NET compilation, Windows PowerShell runtime, and Authenticode signing in environments where local Linux cannot execute those tools.
