param([switch]$NoTaskControl)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
Ensure-Directories

$task = Get-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue
$restartAgent = (-not $NoTaskControl) -and ($null -ne $task)
if ($restartAgent) {
    Write-Host 'Stopping background agent...'
    try { Stop-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 2
}

try {
    Write-Host 'Reading AppControl Manager policy and state...'
    $xml = Join-Path $script:PolicyDir 'BasePolicy.xml'
    $state = Read-State

    if (Test-Path -LiteralPath $xml) {
        $policyId = Get-CIPolicyGuid $xml
        Set-RuleOption -FilePath $xml -Option 3
        Set-RuleOption -FilePath $xml -Option 16
        Set-RuleOption -FilePath $xml -Option 17
        Set-RuleOption -FilePath $xml -Option 9
        Set-RuleOption -FilePath $xml -Option 10
        Set-RuleOption -FilePath $xml -Option 11
        $next = if($state.policy_version) { [int]$state.policy_version + 1 } else { 2 }
        Set-CIPolicyVersion -FilePath $xml -Version ("1.0.0.$next")
    } else {
        $template = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
        if (!(Test-Path $template)) { throw "Windows App Control example policy not found: $template" }
        Copy-Item $template $xml -Force
        Set-CIPolicyIdInfo -FilePath $xml -PolicyName 'AppControl Manager Base Policy' -ResetPolicyID | Out-Null
        Set-CIPolicyVersion -FilePath $xml -Version '1.0.0.1'
        Set-RuleOption -FilePath $xml -Option 3
        Set-RuleOption -FilePath $xml -Option 16
        Set-RuleOption -FilePath $xml -Option 17
        Set-RuleOption -FilePath $xml -Option 9
        Set-RuleOption -FilePath $xml -Option 10
        Set-RuleOption -FilePath $xml -Option 11
        $policyId = Get-CIPolicyGuid $xml
        $next = 1
    }

    $policyId = Get-CIPolicyGuid $xml
    Write-Host "Preparing Audit Mode policy $policyId..."
    $cip = Join-Path $script:PolicyDir ($policyId + '.cip')
    ConvertFrom-CIPolicy $xml $cip | Out-Null
    Write-Host 'Deploying policy with CiTool...'
    CiTool.exe --update-policy $cip -json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "CiTool policy update failed with exit code $LASTEXITCODE" }
    Write-Host 'Refreshing App Control policies...'
    CiTool.exe --refresh -json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "CiTool refresh failed with exit code $LASTEXITCODE" }

    $now=(Get-Date).ToUniversalTime().ToString('o')
    $latest = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue
    $record = if ($latest) { [long]$latest.RecordId } else { 0 }

    $newState = [pscustomobject]@{
        learning_mode=$true
        learning_started=$now
        base_policy_id=$policyId
        last_record_id=$record
        policy_version=$next
    }
    Write-Host 'Saving Learning Mode state...'
    Write-State $newState

    # Verify the state actually survived before restarting the background agent.
    $verify = Read-State
    if (-not $verify.learning_mode -or [string]::IsNullOrWhiteSpace([string]$verify.learning_started) -or [string]::IsNullOrWhiteSpace([string]$verify.base_policy_id)) {
        throw 'Learning policy was applied, but the local AppControl Manager state could not be verified.'
    }

    Write-Host "Learning/Audit mode enabled. Base policy: $policyId" -ForegroundColor Green
    Write-Host "Learning started: $now"
    Write-Host "Event cursor reset to record: $record"
    Write-Host 'Applications not covered by the Windows base policy can run but will be recorded as Event ID 3076.'
} finally {
    if ($restartAgent) {
        Write-Host 'Starting background agent...'
        try { Start-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
    }
}
