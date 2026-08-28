param([switch]$NoTaskControl)
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

    $collectTimer=[System.Diagnostics.Stopwatch]::StartNew()
    $learned=@(& "$PSScriptRoot\Get-LearnedApplications.ps1" -Save)
    $collectTimer.Stop()
    Write-Output ("ACM_STAGE learned-collection elapsed={0:F1}s learned={1}" -f $collectTimer.Elapsed.TotalSeconds,$learned.Count)

    $dedupTimer=[System.Diagnostics.Stopwatch]::StartNew()
    $paths=@($learned | ForEach-Object { $_.file_path } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -Unique)
    $dedupTimer.Stop()
    Write-Output ("ACM_STAGE learned-dedup elapsed={0:F1}s learned={1} unique={2}" -f $dedupTimer.Elapsed.TotalSeconds,$learned.Count,$paths.Count)
    if($paths.Count -gt 0) {
        # Build the learned baseline from the signer/product/version metadata already collected
        # above. The dedicated helper groups safe signer+product families before ConfigCI sees
        # them, while retaining conservative per-file/hash fallbacks for unusual binaries.
        & "$PSScriptRoot\New-LearnedBaselinePolicy.ps1" -LearnedApplications $learned -Name 'AppControl Manager Learned Baseline' | ForEach-Object {
            if(([string]$_).StartsWith('ACM_STAGE')) { Write-Output ([string]$_) }
        }
    }

    $baseTimer=[System.Diagnostics.Stopwatch]::StartNew()
    $xml=Join-Path $script:PolicyDir 'BasePolicy.xml'
    # POC safety: enforce EXE/DLL allowlisting, but do not enforce scripts yet.
    # The current management layer is unsigned PowerShell and must remain runnable.
    Set-RuleOption -FilePath $xml -Option 11
    Set-RuleOption -FilePath $xml -Option 3 -Delete
    $next=[int]$state.policy_version + 1
    Set-CIPolicyVersion -FilePath $xml -Version ("1.0.0.$next")
    $cip=Join-Path $script:PolicyDir ($state.base_policy_id + '.cip')
    ConvertFrom-CIPolicy $xml $cip | Out-Null
    CiTool.exe --update-policy $cip -json | Out-Null
    CiTool.exe --refresh -json | Out-Null

    $baseTimer.Stop()
    Write-Output ("ACM_STAGE base-enforcement elapsed={0:F1}s version={1}" -f $baseTimer.Elapsed.TotalSeconds,$next)
    Update-State -Fields @{ learning_mode=$false; policy_version=$next } | Out-Null
    Write-Host "Enforcement enabled. Learned files processed: $($learned.Count)" -ForegroundColor Green
    Write-Host 'Unknown applications should now generate Code Integrity Event ID 3077 and be blocked.'
    Write-Host 'POC safety: PowerShell/script enforcement remains disabled (rule option 11).' -ForegroundColor Yellow
    $totalTimer.Stop()
    Write-Output ("ACM_STAGE enforcement-total elapsed={0:F1}s learned={1} unique={2}" -f $totalTimer.Elapsed.TotalSeconds,$learned.Count,$paths.Count)
} finally {
    if ($restartAgent) {
        try { Start-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    }
}
