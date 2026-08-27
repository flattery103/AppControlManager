param([switch]$NoTaskControl)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator

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

    $learned=@(& "$PSScriptRoot\Get-LearnedApplications.ps1" -Save)
    if($learned.Count -gt 0) {
        $paths=@($learned | ForEach-Object { $_.file_path } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
        if($paths.Count -gt 0) {
            & "$PSScriptRoot\New-SupplementalForFiles.ps1" -FilePath $paths -Name 'AppControl Manager Learned Baseline' | Out-Null
        }
    }

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

    Update-State -Fields @{ learning_mode=$false; policy_version=$next } | Out-Null
    Write-Host "Enforcement enabled. Learned files processed: $($learned.Count)" -ForegroundColor Green
    Write-Host 'Unknown applications should now generate Code Integrity Event ID 3077 and be blocked.'
    Write-Host 'POC safety: PowerShell/script enforcement remains disabled (rule option 11).' -ForegroundColor Yellow
} finally {
    if ($restartAgent) {
        try { Start-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    }
}
