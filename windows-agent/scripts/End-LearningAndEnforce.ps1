param(
    [switch]$NoTaskControl,
    [string]$FragmentListPath,
    [int]$LearnedCount=0,
    [int]$PreparedCount=0,
    [int]$UnpreparedCount=0
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$totalTimer=[System.Diagnostics.Stopwatch]::StartNew()

$task = Get-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue
$restartAgent = (-not $NoTaskControl) -and ($null -ne $task)
if ($restartAgent) {
    try { Stop-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 2
}

try {
    $state=Read-State
    if (!$state.base_policy_id) { throw 'Base policy has not been created.' }
    if (!$state.learning_started) { throw 'Learning mode has not been started.' }
    Write-Output ("ACM_STAGE learned-final-delta elapsed={0:F1}s learned={1} prepared={2} unprepared={3}" -f 0.0,$LearnedCount,$PreparedCount,$UnpreparedCount)
    if($UnpreparedCount -gt 0){ throw "Cannot enable enforcement because $UnpreparedCount learned authorization rule(s) are unresolved." }

    if($LearnedCount -gt 0){
        if([string]::IsNullOrWhiteSpace($FragmentListPath)){ throw 'Prepared learned fragment list is required when learned applications exist.' }
        & "$PSScriptRoot\Install-LearnedBaselineFromFragments.ps1" -FragmentListPath $FragmentListPath -Name 'AppControl Manager Learned Baseline' | ForEach-Object {
            if(([string]$_).StartsWith('ACM_STAGE') -or ([string]$_).StartsWith('Installed learned baseline') -or ([string]$_).StartsWith('stale learned-baseline policies removed')) { Write-Output ([string]$_) }
        }
    }

    # Keep the base enforcement flip LAST. If fragment preparation or learned-baseline
    # installation fails, the endpoint remains safely in Learning/Audit mode.
    $baseTimer=[System.Diagnostics.Stopwatch]::StartNew()
    $xml=Join-Path $script:PolicyDir 'BasePolicy.xml'
    # Safety: enforce EXE/DLL allowlisting, but do not enforce scripts yet because the
    # management layer still uses PowerShell helpers.
    Set-RuleOption -FilePath $xml -Option 11
    Set-RuleOption -FilePath $xml -Option 3 -Delete
    $next=[int]$state.policy_version + 1
    Set-CIPolicyVersion -FilePath $xml -Version ("1.0.0.$next")
    $cip=Join-Path $script:PolicyDir ($state.base_policy_id + '.cip')
    ConvertFrom-CIPolicy $xml $cip | Out-Null
    CiTool.exe --update-policy $cip -json | Out-Null
    if($LASTEXITCODE -ne 0){ throw "CiTool base policy update failed with exit code $LASTEXITCODE" }
    CiTool.exe --refresh -json | Out-Null
    if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE" }
    $baseTimer.Stop()
    Write-Output ("ACM_STAGE base-enforcement elapsed={0:F1}s version={1}" -f $baseTimer.Elapsed.TotalSeconds,$next)
    Update-State -Fields @{ learning_mode=$false; policy_version=$next } | Out-Null
    Write-Host "Enforcement enabled. Learned files processed: $LearnedCount" -ForegroundColor Green
    Write-Host 'Unknown applications should now generate Code Integrity Event ID 3077 and be blocked.'
    Write-Host 'Safety: PowerShell/script enforcement remains disabled (rule option 11).' -ForegroundColor Yellow
    $totalTimer.Stop()
    Write-Output ("ACM_STAGE enforcement-total elapsed={0:F1}s learned={1} prepared={2} unprepared={3}" -f $totalTimer.Elapsed.TotalSeconds,$LearnedCount,$PreparedCount,$UnpreparedCount)
} finally {
    if ($restartAgent) {
        try { Start-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    }
}
