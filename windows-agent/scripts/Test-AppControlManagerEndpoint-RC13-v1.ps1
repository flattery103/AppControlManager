<#
.SYNOPSIS
Runs repeatable AppControl Manager endpoint health and recovery validation.

.EXAMPLE
.\Test-AppControlManagerEndpoint.ps1 -Mode Health -OutputPath C:\Temp\ACM-Health.json

.EXAMPLE
.\Test-AppControlManagerEndpoint.ps1 -Mode Functional -OutputPath C:\Temp\ACM-Functional.json
#>
[CmdletBinding()]
param(
    [ValidateSet('Health', 'Functional')]
    [string]$Mode = 'Health',

    [string]$OutputPath = (
        Join-Path $env:TEMP (
            'AppControlManager-Validation-{0}.json' -f (
                Get-Date -Format 'yyyyMMdd-HHmmss'
            )
        )
    )
)

$ErrorActionPreference = 'Stop'
$validatorVersion = 'RC13-v1'
$programFiles = 'C:\Program Files\AppControlManager'
$programData = 'C:\ProgramData\AppControlManager'
$serviceNames = @('AppControlManager', 'AppControlManagerRuleWorker')
$results = New-Object System.Collections.Generic.List[object]

function Add-TestResult {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('PASS','WARN','FAIL')][string]$Status,
        [Parameter(Mandatory=$true)][string]$Detail
    )

    $results.Add([pscustomobject]@{
        Name = $Name
        Status = $Status
        Detail = $Detail
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
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        Add-TestResult -Name "JSON: $Path" -Status FAIL `
            -Detail "The file could not be parsed: $($_.Exception.Message)"
        return $null
    }
}

function Get-ObjectProperty {
    param(
        [object]$InputObject,
        [Parameter(Mandatory=$true)][string]$Name
    )

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

function Invoke-SafeRecovery {
    Write-Host "`n=== Functional recovery checks ===" -ForegroundColor Cyan

    foreach ($name in $serviceNames) {
        try {
            $service = Get-Service -Name $name -ErrorAction Stop
            Set-Service -Name $name -StartupType Automatic
            if ($service.Status -ne 'Running') {
                Start-Service -Name $name
                Start-Sleep -Seconds 3
            }
            Add-TestResult -Name "Recovery: $name" -Status PASS `
                -Detail 'Startup is Automatic and the service start was requested if needed.'
        }
        catch {
            Add-TestResult -Name "Recovery: $name" -Status FAIL `
                -Detail $_.Exception.Message
        }
    }

    $tray = @(Get-Process -Name 'AppControlManager.Tray' -ErrorAction SilentlyContinue)
    if ($tray.Count -eq 0) {
        $ensureTray = Join-Path $programFiles 'Scripts\Ensure-TrayRunning.ps1'
        if (-not (Test-Path -LiteralPath $ensureTray)) {
            Add-TestResult -Name 'Recovery: tray' -Status FAIL `
                -Detail "Recovery script is missing: $ensureTray"
        }
        else {
            try {
                $trayRecoveryOutput = @(& powershell.exe -NoProfile `
                    -ExecutionPolicy Bypass -File $ensureTray 2>&1)
                $trayRecoveryExitCode = $LASTEXITCODE
                Start-Sleep -Seconds 3
                $trayAfterRecovery = @(
                    Get-Process -Name 'AppControlManager.Tray' `
                        -ErrorAction SilentlyContinue
                )
                if ($trayRecoveryExitCode -ne 0 -or $trayAfterRecovery.Count -eq 0) {
                    $recoveryDetail = ($trayRecoveryOutput -join ' ').Trim()
                    if ([string]::IsNullOrWhiteSpace($recoveryDetail)) {
                        $recoveryDetail = 'The recovery process did not start an interactive tray.'
                    }
                    Add-TestResult -Name 'Recovery: tray' -Status FAIL `
                        -Detail $recoveryDetail
                }
                else {
                    Add-TestResult -Name 'Recovery: tray' -Status PASS `
                        -Detail 'Interactive tray recovery completed and the tray is running.'
                }
            }
            catch {
                Add-TestResult -Name 'Recovery: tray' -Status FAIL `
                    -Detail $_.Exception.Message
            }
        }
    }
    else {
        Add-TestResult -Name 'Recovery: tray' -Status PASS `
            -Detail 'The interactive tray was already running.'
    }
}

Write-Host "AppControl Manager endpoint validation $validatorVersion ($Mode)" `
    -ForegroundColor Cyan
Write-Host ('Computer: {0}  Started: {1:u}' -f $env:COMPUTERNAME,(Get-Date))

$isAdmin = Test-IsAdministrator
if ($isAdmin) {
    Add-TestResult -Name 'Administrator' -Status PASS `
        -Detail 'Running in an elevated Windows PowerShell session.'
}
else {
    Add-TestResult -Name 'Administrator' -Status FAIL `
        -Detail 'Run Windows PowerShell as Administrator and try again.'
}

if ($Mode -eq 'Functional') {
    if ($isAdmin) {
        Invoke-SafeRecovery
    }
    else {
        Add-TestResult -Name 'Functional recovery' -Status FAIL `
            -Detail 'Functional mode requires elevation; no recovery actions were attempted.'
    }
}

Write-Host "`n=== Installation and services ===" -ForegroundColor Cyan

foreach ($path in @(
    $programFiles,
    $programData,
    (Join-Path $programData 'config.json'),
    (Join-Path $programData 'Policies\BasePolicy.xml'),
    (Join-Path $programData 'agent-service.log')
)) {
    if (Test-Path -LiteralPath $path) {
        Add-TestResult -Name "Required path: $path" -Status PASS -Detail 'Present.'
    }
    else {
        Add-TestResult -Name "Required path: $path" -Status FAIL -Detail 'Missing.'
    }
}

$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object Name -In $serviceNames)
foreach ($name in $serviceNames) {
    $service = $services | Where-Object Name -eq $name | Select-Object -First 1
    if ($null -eq $service) {
        Add-TestResult -Name "Service: $name" -Status FAIL -Detail 'Not installed.'
        continue
    }
    if ($service.State -ne 'Running') {
        Add-TestResult -Name "Service: $name" -Status FAIL `
            -Detail "State=$($service.State); StartMode=$($service.StartMode)."
    }
    elseif ($service.StartMode -ne 'Auto') {
        Add-TestResult -Name "Service: $name" -Status WARN `
            -Detail "Running, but StartMode=$($service.StartMode)."
    }
    else {
        Add-TestResult -Name "Service: $name" -Status PASS `
            -Detail 'Running with Automatic startup.'
    }
}

$expectedRecoveryActions = 'restart/10000/restart/30000/restart/60000'
foreach ($name in $serviceNames) {
    $recoveryOutput = @(& sc.exe qfailure $name 2>&1)
    $recoveryExitCode = $LASTEXITCODE
    $recoveryText = $recoveryOutput -join "`n"
    $failureFlagOutput = @(& sc.exe qfailureflag $name 2>&1)
    $failureFlagExitCode = $LASTEXITCODE
    $failureFlagText = $failureFlagOutput -join "`n"
    $recoveryMatches = [regex]::Matches(
        $recoveryText,
        '(?im)RESTART\s+--\s+Delay\s+=\s+(10000|30000|60000)\s+milliseconds'
    )
    $allRecoveryActions = [regex]::Matches(
        $recoveryText,
        '(?im)(RESTART|RUN PROCESS|REBOOT|NONE)\s+--\s+Delay\s+=\s+\d+\s+milliseconds'
    )
    $recoveryDelays = @(
        $recoveryMatches | ForEach-Object { $_.Groups[1].Value }
    )
    $hasExpectedActions = (
        $recoveryDelays.Count -eq 3 -and
        $allRecoveryActions.Count -eq 3 -and
        ($recoveryDelays -join '/') -eq '10000/30000/60000'
    )
    $hasResetPeriod = $recoveryText -match '(?im)RESET_PERIOD.*86400'
    $hasFailureFlag = $failureFlagText -match '(?im)TRUE'
    if ($recoveryExitCode -ne 0 -or $failureFlagExitCode -ne 0) {
        Add-TestResult -Name "Crash recovery: $name" -Status FAIL `
            -Detail "Could not query recovery configuration: $recoveryText $failureFlagText"
    }
    elseif (-not $hasExpectedActions -or -not $hasResetPeriod -or -not $hasFailureFlag) {
        Add-TestResult -Name "Crash recovery: $name" -Status FAIL `
            -Detail "Expected reset=86400, failureflag=TRUE, and $expectedRecoveryActions. Actual: $recoveryText $failureFlagText"
    }
    else {
        Add-TestResult -Name "Crash recovery: $name" -Status PASS `
            -Detail "Configured for $expectedRecoveryActions with reset=86400 and failureflag=TRUE."
    }
}

$binaryResults = @()
foreach ($name in @('AppControlManager.Service.exe','AppControlManager.Tray.exe')) {
    $path = Join-Path $programFiles $name
    if (-not (Test-Path -LiteralPath $path)) {
        Add-TestResult -Name "Binary: $name" -Status FAIL -Detail 'Missing.'
        continue
    }
    $item = Get-Item -LiteralPath $path
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    $version = [string]$item.VersionInfo.ProductVersion
    $binaryResults += [pscustomobject]@{ Name=$name; Version=$version }
    if ($signature.Status -ne 'Valid') {
        Add-TestResult -Name "Binary: $name" -Status FAIL `
            -Detail "Version=$version; Signature=$($signature.Status)."
    }
    else {
        Add-TestResult -Name "Binary: $name" -Status PASS `
            -Detail "Version=$version; signature valid."
    }
}

if ($binaryResults.Count -eq 2) {
    $versions = @($binaryResults | Select-Object -ExpandProperty Version -Unique)
    if ($versions.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($versions[0])) {
        Add-TestResult -Name 'Binary version agreement' -Status PASS `
            -Detail "Service and tray report $($versions[0])."
    }
    else {
        Add-TestResult -Name 'Binary version agreement' -Status FAIL `
            -Detail (($binaryResults | ForEach-Object { "$($_.Name)=$($_.Version)" }) -join '; ')
    }
}

$trayProcesses = @(Get-CimInstance Win32_Process -Filter "Name='AppControlManager.Tray.exe'" `
    -ErrorAction SilentlyContinue)
if ($trayProcesses.Count -eq 1) {
    Add-TestResult -Name 'Tray singleton' -Status PASS `
        -Detail "One tray process is running (PID $($trayProcesses[0].ProcessId))."
}
elseif ($trayProcesses.Count -eq 0) {
    Add-TestResult -Name 'Tray singleton' -Status FAIL `
        -Detail 'No tray process is running. A logged-on user may be required.'
}
else {
    Add-TestResult -Name 'Tray singleton' -Status FAIL `
        -Detail "$($trayProcesses.Count) tray processes are running."
}

Write-Host "`n=== Communication, updates, and background work ===" -ForegroundColor Cyan

$config = Get-JsonFile -Path (Join-Path $programData 'config.json')
$serverUrl = [string](Get-ObjectProperty -InputObject $config -Name 'server_url')
if ([string]::IsNullOrWhiteSpace($serverUrl)) {
    Add-TestResult -Name 'Server configuration' -Status FAIL `
        -Detail 'config.json does not contain server_url.'
}
else {
    try {
        $response = Invoke-WebRequest -UseBasicParsing `
            -Uri ($serverUrl.TrimEnd('/') + '/health') -TimeoutSec 15
        if ($response.StatusCode -eq 200) {
            Add-TestResult -Name 'Server connectivity' -Status PASS `
                -Detail "Health endpoint returned 200 from $serverUrl."
        }
        else {
            Add-TestResult -Name 'Server connectivity' -Status FAIL `
                -Detail "Health endpoint returned HTTP $($response.StatusCode)."
        }
    }
    catch {
        Add-TestResult -Name 'Server connectivity' -Status FAIL `
            -Detail $_.Exception.Message
    }
}

$serviceLog = Join-Path $programData 'agent-service.log'
if (Test-Path -LiteralPath $serviceLog) {
    $age = (Get-Date) - (Get-Item -LiteralPath $serviceLog).LastWriteTime
    if ($age.TotalMinutes -le 2) {
        Add-TestResult -Name 'Agent activity' -Status PASS `
            -Detail ('Service log updated {0:N1} minute(s) ago.' -f $age.TotalMinutes)
    }
    elseif ($age.TotalMinutes -le 10) {
        Add-TestResult -Name 'Agent activity' -Status WARN `
            -Detail ('Service log updated {0:N1} minute(s) ago.' -f $age.TotalMinutes)
    }
    else {
        Add-TestResult -Name 'Agent activity' -Status FAIL `
            -Detail ('Service log has not changed for {0:N1} minutes.' -f $age.TotalMinutes)
    }

    $recentLog = @(Get-Content -LiteralPath $serviceLog -Tail 250 -ErrorAction SilentlyContinue)
    $recentFailures = @($recentLog | Select-String `
        'unhandled|fatal|command .* failed|rollback failed|service recovery failed')
    if ($recentFailures.Count -eq 0) {
        Add-TestResult -Name 'Recent agent failures' -Status PASS `
            -Detail 'No critical failure pattern found in the newest 250 log lines.'
    }
    else {
        Add-TestResult -Name 'Recent agent failures' -Status WARN `
            -Detail "$($recentFailures.Count) failure line(s) found; review agent-service.log."
    }
}

$updatePath = Join-Path $programData 'Updates\update-status.json'
$update = Get-JsonFile -Path $updatePath
if ($null -eq $update) {
    Add-TestResult -Name 'Agent update state' -Status WARN `
        -Detail 'No update-status.json exists; no update may have run yet.'
}
else {
    $updateStatus = [string](Get-ObjectProperty $update 'status')
    $activeUpdateStates = @('assigned','downloading','staging','preauthorizing','installing')
    if ($updateStatus -eq 'failed') {
        Add-TestResult -Name 'Agent update state' -Status FAIL `
            -Detail ([string](Get-ObjectProperty $update 'result'))
    }
    elseif ($updateStatus -in $activeUpdateStates) {
        $updatedAtText = [string](Get-ObjectProperty $update 'updated_at')
        $updatedAt = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse($updatedAtText, [ref]$updatedAt) -and
            (([datetimeoffset]::UtcNow - $updatedAt.ToUniversalTime()).TotalMinutes -gt 20)) {
            Add-TestResult -Name 'Agent update state' -Status FAIL `
                -Detail "Update is stuck in '$updateStatus'; last change was $updatedAtText."
        }
        else {
            Add-TestResult -Name 'Agent update state' -Status WARN `
                -Detail "Update is currently $updateStatus."
        }
    }
    else {
        Add-TestResult -Name 'Agent update state' -Status PASS `
            -Detail "Status=$updateStatus."
    }
}

$backgroundPath = Join-Path $programData 'background-policy-state.json'
$background = Get-JsonFile -Path $backgroundPath
if ($null -eq $background) {
    Add-TestResult -Name 'Background policy state' -Status WARN `
        -Detail 'No background-policy-state.json exists; no background work may have run yet.'
}
else {
    $rules = @(Get-ObjectProperty $background 'rules')
    $bundles = @(Get-ObjectProperty $background 'bundles')
    $failedRules = @($rules | Where-Object status -eq 'failed').Count
    $failedBundles = @($bundles | Where-Object status -eq 'failed').Count
    $failed = $failedRules + $failedBundles
    $pendingRules = @(
        $rules | Where-Object status -In 'queued','processing','working'
    ).Count
    $pendingBundles = @(
        $bundles | Where-Object status -In 'queued','processing','working'
    ).Count
    $pending = $pendingRules + $pendingBundles
    if ($failed -gt 0) {
        Add-TestResult -Name 'Background policy state' -Status FAIL `
            -Detail "$failed failed job(s); $pending pending job(s)."
    }
    elseif ($pending -gt 0) {
        Add-TestResult -Name 'Background policy state' -Status WARN `
            -Detail "$pending job(s) are still pending."
    }
    else {
        Add-TestResult -Name 'Background policy state' -Status PASS `
            -Detail 'No failed or pending jobs.'
    }
}

$systemDrive = Get-PSDrive -Name ([IO.Path]::GetPathRoot($programData).TrimEnd(':\'))
$freeGb = $systemDrive.Free / 1GB
if ($freeGb -lt 0.5) {
    Add-TestResult -Name 'System drive free space' -Status FAIL `
        -Detail ('Only {0:N2} GB is free.' -f $freeGb)
}
elseif ($freeGb -lt 2) {
    Add-TestResult -Name 'System drive free space' -Status WARN `
        -Detail ('Only {0:N2} GB is free; agent updates need backup space.' -f $freeGb)
}
else {
    Add-TestResult -Name 'System drive free space' -Status PASS `
        -Detail ('{0:N2} GB is free.' -f $freeGb)
}

Write-Host "`n=== Windows App Control ===" -ForegroundColor Cyan

$ciTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
try {
    $policyOutput = & $ciTool -lp -json 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($policyOutput -join "`n") }
    $policyData = $policyOutput | ConvertFrom-Json
    $acmPolicies = @($policyData.Policies | Where-Object {
        $_.FriendlyName -like 'AppControl Manager*'
    })
    $basePolicies = @($acmPolicies | Where-Object {
        $_.FriendlyName -eq 'AppControl Manager Base Policy'
    })
    if ($basePolicies.Count -ne 1) {
        Add-TestResult -Name 'Base policy' -Status FAIL `
            -Detail "Expected one AppControl Manager Base Policy; found $($basePolicies.Count)."
    }
    elseif (-not $basePolicies[0].IsAuthorized -or -not $basePolicies[0].IsEnforced) {
        Add-TestResult -Name 'Base policy' -Status FAIL `
            -Detail "Authorized=$($basePolicies[0].IsAuthorized); Enforced=$($basePolicies[0].IsEnforced)."
    }
    else {
        Add-TestResult -Name 'Base policy' -Status PASS `
            -Detail "Policy $($basePolicies[0].PolicyID) is authorized and enforced."
    }

    if ($basePolicies.Count -eq 1) {
        $baseId = ([string]$basePolicies[0].PolicyID).Trim('{}').ToLowerInvariant()
        $orphans = @($acmPolicies | Where-Object {
            $_.FriendlyName -ne 'AppControl Manager Base Policy' -and
            ([string]$_.BasePolicyID).Trim('{}').ToLowerInvariant() -ne $baseId
        })
        if ($orphans.Count -gt 0) {
            Add-TestResult -Name 'Supplemental policy lineage' -Status FAIL `
                -Detail "$($orphans.Count) AppControl Manager policy/policies reference another base."
        }
        else {
            Add-TestResult -Name 'Supplemental policy lineage' -Status PASS `
                -Detail "$($acmPolicies.Count - 1) supplemental policy/policies reference the active base."
        }
    }
}
catch {
    Add-TestResult -Name 'Windows App Control inventory' -Status FAIL `
        -Detail $_.Exception.Message
}

try {
    $ciEvents = @(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-CodeIntegrity/Operational'
        StartTime=(Get-Date).AddHours(-24)
    } -ErrorAction Stop | Where-Object Id -In 3033,3076,3077)
    if ($ciEvents.Count -eq 0) {
        Add-TestResult -Name 'Code Integrity events' -Status PASS `
            -Detail 'No block/audit events were recorded in the last 24 hours.'
    }
    else {
        Add-TestResult -Name 'Code Integrity events' -Status WARN `
            -Detail "$($ciEvents.Count) block/audit event(s) were recorded in the last 24 hours."
    }
}
catch {
    Add-TestResult -Name 'Code Integrity events' -Status WARN `
        -Detail "Could not read the CodeIntegrity/Operational log: $($_.Exception.Message)"
}

$passCount = @($results | Where-Object Status -eq 'PASS').Count
$warnCount = @($results | Where-Object Status -eq 'WARN').Count
$failCount = @($results | Where-Object Status -eq 'FAIL').Count
$exitCode = if ($failCount -gt 0) { 2 } elseif ($warnCount -gt 0) { 1 } else { 0 }

$report = [ordered]@{
    SchemaVersion = 1
    GeneratedAt = [datetimeoffset]::UtcNow.ToString('O')
    ComputerName = $env:COMPUTERNAME
    ValidatorVersion = $validatorVersion
    Mode = $Mode
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    Summary = [ordered]@{
        Pass = $passCount
        Warn = $warnCount
        Fail = $failCount
        ExitCode = $exitCode
    }
    # Windows PowerShell 5.1 can throw "Argument types do not match" when
    # @() wraps a List[object] created by New-Object. Convert explicitly.
    Results = $results.ToArray()
}

$parent = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "PASS=$passCount  WARN=$warnCount  FAIL=$failCount"
Write-Host "JSON report: $OutputPath"
Write-Host 'Exit codes: 0=pass, 1=warnings, 2=one or more failures.'

$global:LASTEXITCODE = $exitCode
exit $exitCode
