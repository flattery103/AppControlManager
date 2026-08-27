param([switch]$NoTaskControl)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
Ensure-Directories

$task = Get-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue
$restartAgent = (-not $NoTaskControl) -and ($null -ne $task)
if ($restartAgent) {
    try { Stop-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 2
}

try {
    $state=Read-State
    $xml=Join-Path $script:PolicyDir 'BasePolicy.xml'
    if (!(Test-Path $xml)) { throw 'Base policy XML not found.' }
    $policyId=Get-CIPolicyGuid $xml
    Set-RuleOption -FilePath $xml -Option 3
    Set-RuleOption -FilePath $xml -Option 16
    Set-RuleOption -FilePath $xml -Option 17
    Set-RuleOption -FilePath $xml -Option 11
    $next=if($state.policy_version){[int]$state.policy_version + 1}else{2}
    Set-CIPolicyVersion -FilePath $xml -Version ("1.0.0.$next")
    $cip=Join-Path $script:PolicyDir ($policyId + '.cip')
    ConvertFrom-CIPolicy $xml $cip | Out-Null
    CiTool.exe --update-policy $cip -json | Out-Null
    CiTool.exe --refresh -json | Out-Null

    $started=$state.learning_started
    if([string]::IsNullOrWhiteSpace([string]$started)){$started=(Get-Date).ToUniversalTime().ToString('o')}
    Update-State -Fields @{ learning_mode=$true; base_policy_id=$policyId; policy_version=$next; learning_started=$started } | Out-Null
    Write-Host "Base policy returned to Audit Mode. Policy: $policyId" -ForegroundColor Yellow
    Write-Host "Learning start recorded as: $started"
} finally {
    if ($restartAgent) {
        try { Start-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    }
}
