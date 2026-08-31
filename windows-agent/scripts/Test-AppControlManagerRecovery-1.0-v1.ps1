<#
.SYNOPSIS
Disruptive recovery validation for an AppControl Manager disposable test VM.

.EXAMPLE
.\Test-AppControlManagerRecovery-1.0-v1.ps1 -Mode Recovery -OutputPath C:\Temp\ACM-Recovery-1.0-v1.json

.EXAMPLE
.\Test-AppControlManagerRecovery-1.0-v1.ps1 -Mode CrashRecovery -IncludeReboot -OutputPath C:\Temp\ACM-CrashRecovery-1.0-v1.json
#>
[CmdletBinding()]
param(
    [ValidateSet('Recovery', 'CrashRecovery')]
    [string]$Mode = 'Recovery',

    [switch]$IncludeReboot,

    [string]$OutputPath = (
        Join-Path $env:TEMP (
            'AppControlManager-Recovery-1.0-v1-{0}.json' -f (
                Get-Date -Format 'yyyyMMdd-HHmmss'
            )
        )
    ),

    [switch]$ResumeAfterReboot,

    [string]$ContinuationTaskName = 'AppControlManager Recovery Validation 1.0-v1',

    [string]$PreRebootReportPath
)

$ErrorActionPreference = 'Stop'
$testVersion = '1.0-v1'
$recoveryScriptPath = $PSCommandPath
$programFiles = 'C:\Program Files\AppControlManager'
$programData = 'C:\ProgramData\AppControlManager'
$serviceNames = @('AppControlManager', 'AppControlManagerRuleWorker')
$results = New-Object System.Collections.ArrayList
$startedAt = [datetimeoffset]::UtcNow
$serviceLog = Join-Path $programData 'agent-service.log'
$initialLogWrite = if (Test-Path -LiteralPath $serviceLog) {
    (Get-Item -LiteralPath $serviceLog).LastWriteTimeUtc
} else { [datetime]::MinValue }

function Add-TestResult {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('PASS','WARN','FAIL')][string]$Status,
        [Parameter(Mandatory=$true)][string]$Detail,
        [double]$ElapsedSeconds = 0
    )

    $null = $results.Add([pscustomobject]@{
        Name = $Name
        Status = $Status
        Detail = $Detail
        ElapsedSeconds = [math]::Round($ElapsedSeconds, 1)
    })
    $color = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        default { 'Red' }
    }
    Write-Host ('[{0}] {1}: {2}' -f $Status,$Name,$Detail) -ForegroundColor $color
}

function Get-JsonFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch { return $null }
}

function Get-PropertyValue {
    param([object]$InputObject,[Parameter(Mandatory=$true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-ServiceRecord {
    param([Parameter(Mandatory=$true)][string]$Name)
    return Get-CimInstance Win32_Service -Filter "Name='$Name'" `
        -ErrorAction SilentlyContinue
}

function Wait-ServiceState {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$State,
        [int]$TimeoutSeconds = 30,
        [int]$DifferentFromProcessId = 0
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $record = Get-ServiceRecord -Name $Name
        if ($null -ne $record -and $record.State -eq $State) {
            if ($DifferentFromProcessId -eq 0 -or
                [int]$record.ProcessId -ne $DifferentFromProcessId) {
                return $record
            }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $null
}

function Restore-Service {
    param([Parameter(Mandatory=$true)][string]$Name)
    try {
        Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
        $service = Get-Service -Name $Name -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            Start-Service -Name $Name -ErrorAction Stop
        }
        return $null -ne (Wait-ServiceState -Name $Name -State Running -TimeoutSeconds 30)
    }
    catch { return $false }
}

function Write-Report {
    param([Parameter(Mandatory=$true)][string]$Path)

    $passCount = @($results | Where-Object Status -eq 'PASS').Count
    $warnCount = @($results | Where-Object Status -eq 'WARN').Count
    $failCount = @($results | Where-Object Status -eq 'FAIL').Count
    $exitCode = if ($failCount -gt 0) { 2 } elseif ($warnCount -gt 0) { 1 } else { 0 }
    $report = [ordered]@{
        SchemaVersion = 1
        TestVersion = $testVersion
        GeneratedAt = [datetimeoffset]::UtcNow.ToString('O')
        StartedAt = $startedAt.ToString('O')
        ComputerName = $env:COMPUTERNAME
        Mode = $Mode
        IncludeReboot = [bool]$IncludeReboot
        Summary = [ordered]@{
            Pass = $passCount
            Warn = $warnCount
            Fail = $failCount
            ExitCode = $exitCode
        }
        Results = @($results | ForEach-Object { $_ })
    }
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $Path -Encoding UTF8
    return $exitCode
}

function Stop-WithVerification {
    param([Parameter(Mandatory=$true)][string]$Name)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        $stopped = Wait-ServiceState -Name $Name -State Stopped -TimeoutSeconds 30
        $timer.Stop()
        if ($null -eq $stopped) {
            Add-TestResult -Name "Controlled stop: $Name" -Status FAIL `
                -Detail 'Service did not reach Stopped within 30 seconds.' `
                -ElapsedSeconds $timer.Elapsed.TotalSeconds
            return $false
        }
        Add-TestResult -Name "Controlled stop: $Name" -Status PASS `
            -Detail 'Service reached Stopped.' -ElapsedSeconds $timer.Elapsed.TotalSeconds
        return $true
    }
    catch {
        $timer.Stop()
        Add-TestResult -Name "Controlled stop: $Name" -Status FAIL `
            -Detail $_.Exception.Message -ElapsedSeconds $timer.Elapsed.TotalSeconds
        return $false
    }
}

function Invoke-ControlledRecoveryTest {
    param([Parameter(Mandatory=$true)][string]$Name)
    try {
        if (-not (Stop-WithVerification -Name $Name)) { return }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $restored = Restore-Service -Name $Name
        $timer.Stop()
        if ($restored) {
            Add-TestResult -Name "Documented recovery: $Name" -Status PASS `
                -Detail 'Automatic startup was restored and the service is running.' `
                -ElapsedSeconds $timer.Elapsed.TotalSeconds
        }
        else {
            Add-TestResult -Name "Documented recovery: $Name" -Status FAIL `
                -Detail 'The documented recovery did not restore the service.' `
                -ElapsedSeconds $timer.Elapsed.TotalSeconds
        }
    }
    finally {
        if (-not (Restore-Service -Name $Name)) {
            Add-TestResult -Name "Final restore: $Name" -Status FAIL `
                -Detail 'The service could not be restored after the controlled test.'
        }
    }
}

function Invoke-ServiceCrashTest {
    param([Parameter(Mandatory=$true)][string]$Name)

    $original = Get-ServiceRecord -Name $Name
    if ($null -eq $original -or $original.State -ne 'Running' -or
        [int]$original.ProcessId -le 0) {
        Add-TestResult -Name "Automatic crash recovery: $Name" -Status FAIL `
            -Detail 'Service was not running with a valid process before the test.'
        return
    }
    $OriginalProcessId = [int]$original.ProcessId
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $AutomaticCrashRecovery = $false
    try {
        Stop-Process -Id $OriginalProcessId -Force -ErrorAction Stop
        $restarted = Wait-ServiceState -Name $Name -State Running `
            -TimeoutSeconds 75 -DifferentFromProcessId $OriginalProcessId
        $AutomaticCrashRecovery = $null -ne $restarted
        $timer.Stop()
        if ($AutomaticCrashRecovery) {
            Add-TestResult -Name "Automatic crash recovery: $Name" -Status PASS `
                -Detail "Service restarted with PID $($restarted.ProcessId)." `
                -ElapsedSeconds $timer.Elapsed.TotalSeconds
        }
        else {
            Add-TestResult -Name "Automatic crash recovery: $Name" -Status FAIL `
                -Detail 'Windows did not automatically restart the crashed service within 75 seconds.' `
                -ElapsedSeconds $timer.Elapsed.TotalSeconds
        }
    }
    catch {
        $timer.Stop()
        Add-TestResult -Name "Automatic crash recovery: $Name" -Status FAIL `
            -Detail $_.Exception.Message -ElapsedSeconds $timer.Elapsed.TotalSeconds
    }
    finally {
        if (-not $AutomaticCrashRecovery -and -not (Restore-Service -Name $Name)) {
            Add-TestResult -Name "Final restore: $Name" -Status FAIL `
                -Detail 'The service could not be restored after the crash test.'
        }
    }
}

function Invoke-TrayRecoveryTest {
    $shell = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
    $sessionId = [int]$shell.SessionId
    $trayBefore = @(Get-CimInstance Win32_Process `
        -Filter "Name='AppControlManager.Tray.exe'" | Where-Object {
            [int]$_.SessionId -eq $sessionId
        })
    if ($trayBefore.Count -eq 0) {
        Add-TestResult -Name 'Tray test precondition' -Status FAIL `
            -Detail "No tray was running in session $sessionId before the test."
        return
    }

    try {
        foreach ($tray in $trayBefore) {
            Stop-Process -Id ([int]$tray.ProcessId) -Force -ErrorAction Stop
        }
        Start-Sleep -Seconds 2
        $ensureTray = Join-Path $programFiles 'Scripts\Ensure-TrayRunning.ps1'
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $ensureTray 2>&1)
        $helperExitCode = $LASTEXITCODE
        $deadline = (Get-Date).AddSeconds(20)
        do {
            $trayAfter = @(Get-CimInstance Win32_Process `
                -Filter "Name='AppControlManager.Tray.exe'" | Where-Object {
                    [int]$_.SessionId -eq $sessionId
                })
            if ($trayAfter.Count -eq 1) { break }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)
        $timer.Stop()
        if ($helperExitCode -eq 0 -and $trayAfter.Count -eq 1) {
            Add-TestResult -Name 'Tray singleton after recovery' -Status PASS `
                -Detail "One tray is running in session $sessionId (PID $($trayAfter[0].ProcessId))." `
                -ElapsedSeconds $timer.Elapsed.TotalSeconds
        }
        else {
            Add-TestResult -Name 'Tray singleton after recovery' -Status FAIL `
                -Detail "Count=$($trayAfter.Count); helper exit=$helperExitCode; $($output -join ' ')" `
                -ElapsedSeconds $timer.Elapsed.TotalSeconds
        }
    }
    catch {
        Add-TestResult -Name 'Tray singleton after recovery' -Status FAIL `
            -Detail $_.Exception.Message
    }
    finally {
        $remaining = @(Get-CimInstance Win32_Process `
            -Filter "Name='AppControlManager.Tray.exe'" | Where-Object {
                [int]$_.SessionId -eq $sessionId
            })
        if ($remaining.Count -eq 0) {
            $ensureTray = Join-Path $programFiles 'Scripts\Ensure-TrayRunning.ps1'
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ensureTray | Out-Null
        }
    }
}

function Test-SafetyGates {
    $blocked = $false
    $update = Get-JsonFile -Path (Join-Path $programData 'Updates\update-status.json')
    $updateStatus = [string](Get-PropertyValue $update 'status')
    if ($updateStatus -in @(
        'assigned','downloading','staging','preauthorizing','installing'
    )) {
        Add-TestResult -Name 'Safety gate: agent update' -Status FAIL `
            -Detail "Agent update status is $updateStatus."
        $blocked = $true
    }
    else {
        Add-TestResult -Name 'Safety gate: agent update' -Status PASS `
            -Detail "No active update (status=$updateStatus)."
    }

    $background = Get-JsonFile -Path (
        Join-Path $programData 'background-policy-state.json'
    )
    $activeBackground = @()
    if ($null -ne $background) {
        $activeBackground += @(Get-PropertyValue $background 'rules' | Where-Object {
            $_.status -in @('queued','processing','working')
        })
        $activeBackground += @(Get-PropertyValue $background 'bundles' | Where-Object {
            $_.status -in @('queued','processing','working')
        })
    }
    if ($activeBackground.Count -gt 0) {
        Add-TestResult -Name 'Safety gate: background policy' -Status FAIL `
            -Detail "$($activeBackground.Count) background job(s) are active."
        $blocked = $true
    }
    else {
        Add-TestResult -Name 'Safety gate: background policy' -Status PASS `
            -Detail 'No queued or processing background work.'
    }

    $installation = Get-JsonFile -Path (
        Join-Path $programData 'installation-mode.json'
    )
    if ([bool](Get-PropertyValue $installation 'active')) {
        Add-TestResult -Name 'Safety gate: installation mode' -Status FAIL `
            -Detail 'Installation mode is active.'
        $blocked = $true
    }
    else {
        Add-TestResult -Name 'Safety gate: installation mode' -Status PASS `
            -Detail 'Installation mode is inactive.'
    }
    return -not $blocked
}

function Invoke-FinalHealthValidation {
    $validatorNames = @(
        (Join-Path $PSScriptRoot 'Test-AppControlManagerEndpoint-1.0-v1.ps1'),
        (Join-Path $programFiles 'Scripts\Test-AppControlManagerEndpoint-1.0-v1.ps1')
    )
    $validator = $validatorNames | Where-Object {
        Test-Path -LiteralPath $_
    } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace([string]$validator)) {
        Add-TestResult -Name 'Final endpoint health validation' -Status FAIL `
            -Detail 'Test-AppControlManagerEndpoint-1.0-v1.ps1 was not found beside this script or in Program Files.'
        return
    }
    $healthReport = [IO.Path]::ChangeExtension($OutputPath, '.health.json')
    $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $validator -Mode Health -OutputPath $healthReport 2>&1)
    $healthExit = $LASTEXITCODE
    if ($healthExit -le 1 -and (Test-Path -LiteralPath $healthReport)) {
        Add-TestResult -Name 'Final endpoint health validation' -Status PASS `
            -Detail "Health validator exit=$healthExit; report=$healthReport."
    }
    else {
        Add-TestResult -Name 'Final endpoint health validation' -Status FAIL `
            -Detail "Health validator exit=$healthExit; $($output -join ' ')"
    }
}

function Schedule-RebootContinuation {
    $scriptPath = $recoveryScriptPath
    $prePath = [IO.Path]::ChangeExtension($OutputPath, '.pre-reboot.json')
    $null = Write-Report -Path $prePath
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode {1} -OutputPath "{2}" -IncludeReboot -ResumeAfterReboot -ContinuationTaskName "{3}" -PreRebootReportPath "{4}"' -f `
        $scriptPath,$Mode,$OutputPath,$ContinuationTaskName,$prePath
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser `
        -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $ContinuationTaskName -Action $action `
        -Trigger $trigger -Principal $principal -Force | Out-Null
    Add-TestResult -Name 'Reboot continuation' -Status PASS `
        -Detail "One-time validation task registered for $currentUser."
    $null = Write-Report -Path $prePath
    Write-Host "Pre-reboot report: $prePath"
    Write-Host 'Windows will restart now. Sign in to allow validation to continue.'
    Restart-Computer -Force
}

Write-Host "AppControl Manager recovery validation $testVersion ($Mode)" `
    -ForegroundColor Cyan
Write-Host ('Computer: {0}  Started: {1:u}' -f $env:COMPUTERNAME,(Get-Date))
Write-Host 'WARNING: This script intentionally stops AppControl Manager components.' `
    -ForegroundColor Yellow

if (-not (Test-IsAdministrator)) {
    Add-TestResult -Name 'Administrator' -Status FAIL `
        -Detail 'Run Windows PowerShell as Administrator.'
    $exitCode = Write-Report -Path $OutputPath
    $global:LASTEXITCODE = $exitCode
    exit $exitCode
}
Add-TestResult -Name 'Administrator' -Status PASS `
    -Detail 'Running in an elevated Windows PowerShell session.'

if ($Mode -eq 'CrashRecovery' -and -not $IncludeReboot -and
    -not $ResumeAfterReboot) {
    Add-TestResult -Name 'Crash recovery safety' -Status FAIL `
        -Detail 'CrashRecovery requires -IncludeReboot so Windows resets the Service Control Manager failure counters after testing.'
    $exitCode = Write-Report -Path $OutputPath
    $global:LASTEXITCODE = $exitCode
    exit $exitCode
}

if ($ResumeAfterReboot) {
    Unregister-ScheduledTask -TaskName $ContinuationTaskName -Confirm:$false `
        -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($PreRebootReportPath)) {
        $preReport = Get-JsonFile -Path $PreRebootReportPath
        foreach ($item in @(Get-PropertyValue $preReport 'Results')) {
            $null = $results.Add($item)
        }
    }
    Start-Sleep -Seconds 20
    foreach ($name in $serviceNames) {
        $record = Get-ServiceRecord -Name $name
        if ($null -ne $record -and $record.State -eq 'Running' -and
            $record.StartMode -eq 'Auto') {
            Add-TestResult -Name "Post-reboot service: $name" -Status PASS `
                -Detail 'Running with Automatic startup.'
        }
        else {
            Add-TestResult -Name "Post-reboot service: $name" -Status FAIL `
                -Detail "State=$($record.State); StartMode=$($record.StartMode)."
        }
    }
    $trayDeadline = (Get-Date).AddSeconds(60)
    do {
        $tray = @(Get-Process -Name 'AppControlManager.Tray' `
            -ErrorAction SilentlyContinue)
        if ($tray.Count -gt 0) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $trayDeadline)
    if ($tray.Count -eq 1) {
        Add-TestResult -Name 'Post-reboot tray' -Status PASS `
            -Detail "One tray is running (PID $($tray[0].Id))."
    }
    else {
        Add-TestResult -Name 'Post-reboot tray' -Status FAIL `
            -Detail "$($tray.Count) tray process(es) are running."
    }
    Invoke-FinalHealthValidation
}
else {
    if (-not (Test-SafetyGates)) {
        Add-TestResult -Name 'Safety gate' -Status FAIL `
            -Detail 'Recovery validation was canceled without disrupting the endpoint.'
        $exitCode = Write-Report -Path $OutputPath
        $global:LASTEXITCODE = $exitCode
        exit $exitCode
    }

    foreach ($name in @('AppControlManagerRuleWorker','AppControlManager')) {
        Invoke-ControlledRecoveryTest -Name $name
    }
    Invoke-TrayRecoveryTest

    if ($Mode -eq 'CrashRecovery') {
        foreach ($name in @('AppControlManagerRuleWorker','AppControlManager')) {
            Invoke-ServiceCrashTest -Name $name
        }
    }

    $logDeadline = (Get-Date).AddSeconds(90)
    do {
        $currentLogWrite = if (Test-Path -LiteralPath $serviceLog) {
            (Get-Item -LiteralPath $serviceLog).LastWriteTimeUtc
        } else { [datetime]::MinValue }
        if ($currentLogWrite -gt $initialLogWrite) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $logDeadline)
    if ($currentLogWrite -gt $initialLogWrite) {
        Add-TestResult -Name 'Agent activity resumed' -Status PASS `
            -Detail "Service log advanced to $currentLogWrite UTC."
    }
    else {
        Add-TestResult -Name 'Agent activity resumed' -Status FAIL `
            -Detail 'Service log did not advance within 90 seconds.'
    }

    Invoke-FinalHealthValidation

    if ($IncludeReboot) {
        $currentFailures = @($results | Where-Object Status -eq 'FAIL').Count
        if ($Mode -eq 'CrashRecovery' -or $currentFailures -eq 0) {
            Schedule-RebootContinuation
            exit 0
        }
        Add-TestResult -Name 'Reboot continuation' -Status WARN `
            -Detail 'Reboot was skipped because a pre-reboot test failed.'
    }
}

$exitCode = Write-Report -Path $OutputPath
$summary = Get-JsonFile -Path $OutputPath
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host ('PASS={0}  WARN={1}  FAIL={2}' -f `
    $summary.Summary.Pass,$summary.Summary.Warn,$summary.Summary.Fail)
Write-Host "JSON report: $OutputPath"
Write-Host 'Exit codes: 0=pass, 1=warnings, 2=one or more failures.'
$global:LASTEXITCODE = $exitCode
exit $exitCode
