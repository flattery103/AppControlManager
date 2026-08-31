# AppControl Manager 1.0.0-rc.12 Endpoint Service Recovery

Use this procedure when an enrolled Windows device is Offline and either `AppControlManager` or `AppControlManagerRuleWorker` is stopped. Run it in Windows PowerShell as Administrator. Do not queue another agent update until both services are running and the endpoint has sent a new heartbeat.

## 1. Record the current state

```powershell
$ErrorActionPreference = 'Continue'
$programData = 'C:\ProgramData\AppControlManager'

Get-CimInstance Win32_Service |
    Where-Object Name -In 'AppControlManager','AppControlManagerRuleWorker' |
    Select-Object Name,State,StartMode,ExitCode,ServiceSpecificExitCode,PathName |
    Format-List

Get-Content "$programData\Updates\update-status.json" -Raw -ErrorAction SilentlyContinue
Get-Content "$programData\agent-service.log" -Tail 100 -ErrorAction SilentlyContinue
Get-Content "$programData\RuleWorker\rule-worker.log" -Tail 50 -ErrorAction SilentlyContinue
```

Keep this output with the incident. It identifies whether the stop followed an update, policy operation, Windows shutdown, or service-start failure.

## 2. Start and verify the services

```powershell
$ErrorActionPreference = 'Stop'

Set-Service AppControlManager -StartupType Automatic
Set-Service AppControlManagerRuleWorker -StartupType Automatic

Start-Service AppControlManager
Start-Sleep -Seconds 5

if ((Get-Service AppControlManagerRuleWorker).Status -ne 'Running') {
    Start-Service AppControlManagerRuleWorker
}

Start-Sleep -Seconds 15

$services = Get-Service AppControlManager,AppControlManagerRuleWorker
$services | Format-Table Name,Status,StartType -AutoSize

if (@($services | Where-Object Status -ne 'Running').Count -ne 0) {
    throw 'AppControl Manager service recovery did not remain healthy.'
}
```

The main service is started first because it owns Rule Worker provisioning and repair. The explicit Rule Worker start covers an already-provisioned worker that did not start automatically.

## 3. Confirm endpoint communication

```powershell
Get-Content 'C:\ProgramData\AppControlManager\agent-service.log' -Tail 60 |
    Select-String 'heartbeat|command|agent-update|failed'
```

Refresh the server device page. Confirm the device becomes Online, **Last Seen** advances, and the detailed update state is no longer stuck. Allow at least one normal heartbeat interval.

## 4. If either service stops again

Do not repeatedly restart it or assign another update. Collect these diagnostics:

```powershell
$since = (Get-Date).AddMinutes(-30)

Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} |
    Where-Object ProviderName -eq 'Service Control Manager' |
    Select-Object TimeCreated,Id,LevelDisplayName,Message |
    Format-List

Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$since} |
    Where-Object ProviderName -In '.NET Runtime','Application Error','Windows Error Reporting' |
    Select-Object TimeCreated,Id,LevelDisplayName,Message |
    Format-List

Get-Content 'C:\ProgramData\AppControlManager\Updates\update-status.json' -Raw -ErrorAction SilentlyContinue
Get-Content 'C:\ProgramData\AppControlManager\agent-service.log' -Tail 200 -ErrorAction SilentlyContinue
Get-Content 'C:\ProgramData\AppControlManager\RuleWorker\rule-worker.log' -Tail 100 -ErrorAction SilentlyContinue
```

Escalate with the captured output. Use the signed installer repair only after the failure is understood; it preserves enrollment and policy data. Do not manually delete WDAC policies or `C:\ProgramData\AppControlManager` during service recovery.
