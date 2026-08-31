# AppControl Manager Recovery Validation

`Test-AppControlManagerRecovery-1.0-v1.ps1` automates disruptive service, tray, crash, and optional reboot recovery tests. Run it only on a **disposable test VM** or an endpoint with a current restorable snapshot. Run Windows PowerShell as Administrator while logged into the interactive desktop.

Keep `Test-AppControlManagerEndpoint-1.0-v1.ps1` in the same directory. The recovery suite invokes it at the end and saves a separate health report.

The script refuses to begin when an agent update, installation mode, or queued/processing background-policy operation is active. If a test fails, it makes a final service or tray restoration attempt before exiting.

## Controlled recovery

This mode stops each service normally, restores Automatic startup, starts it, terminates the tray in the current session, invokes the production tray-recovery helper, verifies exactly one tray, confirms agent log activity resumes, and runs the Health validator.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$env:USERPROFILE\Downloads\Test-AppControlManagerRecovery-1.0-v1.ps1" `
    -Mode Recovery `
    -OutputPath C:\Temp\ACM-Recovery-1.0-v1.json
```

## Crash recovery

CrashRecovery includes the controlled tests, then force-terminates each service process separately. It waits up to 75 seconds for Windows to restart that service with a new process ID, covering the third configured 60-second recovery action. A failed automatic restart is recorded as a failure, after which the script restores the service manually so the endpoint is not deliberately left offline.

`-IncludeReboot` is mandatory with CrashRecovery. Windows keeps each service's failure count in memory since boot, and there is no supported command to reset that counter directly. The required reboot clears the deliberately consumed first-failure state and the one-time continuation verifies the endpoint after sign-in. The reboot still occurs if a crash assertion fails, so the test VM is not left on a later recovery action.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$env:USERPROFILE\Downloads\Test-AppControlManagerRecovery-1.0-v1.ps1" `
    -Mode CrashRecovery `
    -IncludeReboot `
    -OutputPath C:\Temp\ACM-CrashRecovery-1.0-v1.json
```

## Reboot continuation

Add `-IncludeReboot` to either command to register a one-time, highest-privilege task for the current administrator and restart Windows. Sign in after the reboot. The task verifies both services, the tray, and complete endpoint health, writes the final JSON report, then removes itself.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File "$env:USERPROFILE\Downloads\Test-AppControlManagerRecovery-1.0-v1.ps1" `
    -Mode Recovery `
    -IncludeReboot `
    -OutputPath C:\Temp\ACM-Recovery-Reboot-1.0-v1.json
```

Do not run these tests during an installation, update, approval, revocation, policy generation, or background-policy operation. The script is intentionally disruptive even though it contains restoration safeguards.
