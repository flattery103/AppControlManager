# AppControl Manager Endpoint Validation

The installed `Test-AppControlManagerEndpoint-1.0-v1.ps1` provides a repeatable endpoint smoke test and saves the complete result as JSON. Run it in **Windows PowerShell as Administrator** on an enrolled Windows device. It also verifies the three configured Service Control Manager restart actions and the 24-hour failure reset period for both endpoint services. Standalone diagnostic downloads use a unique versioned filename and print the same version in their console header, preventing an older browser download from being mistaken for the current script.

The script does not approve, revoke, block, unblock, change App Control mode, remove policies, uninstall the agent, or restart a healthy service.

## Health mode

Health mode is read-only. It checks installation files, both services, the tray singleton, binary versions and signatures, server connectivity, agent activity, update state, background policy work, disk space, installed AppControl Manager policy lineage, and recent Code Integrity activity.

```powershell
Set-Location 'C:\Program Files\AppControlManager\Scripts'

.\Test-AppControlManagerEndpoint-1.0-v1.ps1 -Mode Health
```

Save the report at a specific location:

```powershell
.\Test-AppControlManagerEndpoint-1.0-v1.ps1 `
    -Mode Health `
    -OutputPath 'C:\Temp\ACM-Health.json'
```

## Functional mode

Functional mode performs the same validation after safely repairing service startup and availability. It sets both AppControl Manager services to Automatic, starts either service if stopped, and invokes the installed tray-recovery script only when no tray is running. It does not deliberately stop a healthy component.

```powershell
.\Test-AppControlManagerEndpoint-1.0-v1.ps1 `
    -Mode Functional `
    -OutputPath 'C:\Temp\ACM-Functional.json'
```

Functional mode is appropriate after a reboot, agent update, or reported Offline condition. Use Health mode for routine checks.

## Reading the result

- `PASS`: the check met its release requirement.
- `WARN`: review is recommended, but the condition is not necessarily a failure. Active background work and recent Code Integrity events are examples.
- `FAIL`: a required component is missing, stopped, invalid, unreachable, stuck, or misconfigured.

The process exit code is `0` for a clean pass, `1` when warnings exist without failures, and `2` when one or more checks fail. The JSON report contains the same summary and every test result, making it suitable for release records or later server-side ingestion.

Do not use Functional mode as a substitute for diagnosing a service that repeatedly stops. Follow `ENDPOINT-SERVICE-RECOVERY.md` and preserve the logs before reinstalling or assigning another update.
