param([switch]$Policies)
. "$PSScriptRoot\Common.ps1"
$state=Read-State
$xml=Join-Path $script:PolicyDir 'BasePolicy.xml'
$audit=Test-PolicyAuditMode $xml
$scriptDisabled=Test-PolicyScriptEnforcementDisabled $xml
$actualMode = if($null -eq $audit){'NO APPGUARD BASE POLICY'}elseif($audit){'LEARNING/AUDIT'}else{'ENFORCEMENT'}
$stateMode = if($state.learning_mode){'LEARNING/AUDIT'}else{'ENFORCEMENT'}
Write-Host 'Agent script version: 0.1.8'
Write-Host "Mode (policy XML): $actualMode"
Write-Host "Mode (state file): $stateMode"
$scriptMode = if($null -eq $scriptDisabled){'UNKNOWN'}elseif($scriptDisabled){'DISABLED (POC SAFETY)'}else{'ENABLED'}
Write-Host "Script enforcement: $scriptMode"
Write-Host "Base Policy: $($state.base_policy_id)"
Write-Host "Learning started: $($state.learning_started)"
Write-Host "Last CI record sent: $($state.last_record_id)"
if (($actualMode -eq 'LEARNING/AUDIT') -and ($stateMode -ne 'LEARNING/AUDIT' -or [string]::IsNullOrWhiteSpace([string]$state.base_policy_id) -or [string]::IsNullOrWhiteSpace([string]$state.learning_started))) {
    Write-Host ''
    Write-Warning 'Policy is in Audit Mode but local state is incomplete. Run Start-LearningMode.ps1 to repair it.'
}
if($Policies) {
    Write-Host ''
    CiTool.exe --list-policies -json
}
