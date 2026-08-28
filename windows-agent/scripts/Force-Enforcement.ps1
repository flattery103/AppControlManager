param([switch]$NoTaskControl)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state=Read-State
if(!$state.base_policy_id){ throw 'Base policy has not been created.' }
$xml=Join-Path $script:PolicyDir 'BasePolicy.xml'
if(-not (Test-Path -LiteralPath $xml)){ throw "Base policy XML not found: $xml" }
Set-RuleOption -FilePath $xml -Option 11
Set-RuleOption -FilePath $xml -Option 3 -Delete
$next=if($state.policy_version){ [int]$state.policy_version + 1 } else { 2 }
Set-CIPolicyVersion -FilePath $xml -Version ("1.0.0.$next")
$cip=Join-Path $script:PolicyDir ($state.base_policy_id + '.cip')
ConvertFrom-CIPolicy $xml $cip | Out-Null
CiTool.exe --update-policy $cip -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool base policy update failed with exit code $LASTEXITCODE" }
CiTool.exe --refresh -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE" }
Update-State -Fields @{ learning_mode=$false; policy_version=$next } | Out-Null
Write-Output ("ACM_STAGE force-enforcement version={0}" -f $next)
