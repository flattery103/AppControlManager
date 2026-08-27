# AppControl Manager 0.13.1


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
