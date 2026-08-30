$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script = Get-Content -LiteralPath (Join-Path $root 'windows-agent/scripts/Apply-AgentUninstall.ps1') -Raw

if ($script -notmatch 'AppControlManagerRuleWorker') { throw 'Uninstall does not remove the rule-worker service.' }
if ($script -notmatch 'OperationResult"\\s\*:\\s\*-2147024894') { throw 'Uninstall does not tolerate an already-absent policy.' }
if ($script -notmatch "FriendlyName -like 'AppControl Manager\*'") { throw 'Uninstall no longer limits policy cleanup to AppControl Manager policies.' }
if ($script -notmatch "FriendlyName -like 'AppGuard POC\*'") { throw 'Uninstall no longer cleans up legacy AppGuard POC policies.' }
if ($script -notmatch "\*Base Policy\*"){ throw 'Uninstall does not preserve base-policy-last ordering.' }
if ($script.IndexOf("Send-OffboardResult `$true") -lt $script.IndexOf("Remove-Item -LiteralPath `$programData")) { throw 'Uninstall reports success before local state removal.' }

Write-Host 'Agent uninstall behavior tests passed.'
