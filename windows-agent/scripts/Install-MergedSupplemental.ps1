param(
    [Parameter(Mandatory=$true)][string]$FragmentListPath,
    [Parameter(Mandatory=$true)][string]$Name,
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state=Read-State
if(!$state.base_policy_id){ throw 'Base policy has not been created.' }
if(-not (Test-Path -LiteralPath $FragmentListPath -PathType Leaf)){ throw "Fragment list does not exist: $FragmentListPath" }
$raw=Get-Content -LiteralPath $FragmentListPath -Raw -Encoding UTF8
$fragments=[string[]](ConvertFrom-Json -InputObject $raw)
$fragments=@($fragments | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
if($fragments.Count -lt 1){ throw 'No rule fragments were supplied.' }
foreach($fragment in $fragments){ if(-not (Test-Path -LiteralPath $fragment -PathType Leaf)){ throw "Rule fragment does not exist: $fragment" } }

$dir=Join-Path $env:ProgramData 'AppControlManager\Policies'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd-HHmmssfff'
$mergedXml=Join-Path $dir "Background-$stamp.xml"
$mergeTimer=[Diagnostics.Stopwatch]::StartNew()
Merge-CIPolicy -PolicyPaths ([string[]]$fragments) -OutputFilePath $mergedXml
Set-CIPolicyIdInfo -FilePath $mergedXml -PolicyName $Name -ResetPolicyID | Out-Null
Set-CIPolicyIdInfo -FilePath $mergedXml -SupplementsBasePolicyID ([guid]$state.base_policy_id) | Out-Null
Set-CIPolicyVersion -FilePath $mergedXml -Version '1.0.0.0'
$xml=[xml](Get-Content -LiteralPath $mergedXml -Raw)
$policyId=[string]$xml.SiPolicy.PolicyID
if([string]::IsNullOrWhiteSpace($policyId)){ throw 'Merged background policy did not contain a PolicyID.' }
$mergeTimer.Stop()
Write-Output ("ACM_STAGE background-policy-merge elapsed={0:F1}s fragments={1}" -f $mergeTimer.Elapsed.TotalSeconds,$fragments.Count)

$cip=Join-Path $dir ((($policyId -replace '[{}]','').ToUpperInvariant())+'.cip')
$installTimer=[Diagnostics.Stopwatch]::StartNew()
ConvertFrom-CIPolicy -XmlFilePath $mergedXml -BinaryFilePath $cip
& CiTool.exe --update-policy $cip -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool update-policy failed with exit code $LASTEXITCODE" }
& CiTool.exe --refresh -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE" }
$listing=(CiTool.exe -lp -json | ConvertFrom-Json).Policies
$normalized=($policyId -replace '[{}]','').ToLowerInvariant()
$installed=@($listing | Where-Object { (([string]$_.PolicyID) -replace '[{}]','').ToLowerInvariant() -eq $normalized }) | Select-Object -First 1
if($null -eq $installed){ throw "Installed background policy $policyId was not returned by CiTool." }
$enforced=$true
if($installed.PSObject.Properties.Name -contains 'IsCurrentlyEnforced'){ $enforced=[bool]$installed.IsCurrentlyEnforced }
$authorized=$true
if($installed.PSObject.Properties.Name -contains 'IsAuthorized'){ $authorized=[bool]$installed.IsAuthorized }
if(-not $enforced -or -not $authorized){ throw "Installed background policy $policyId is not enforced/authorized." }
$installTimer.Stop()
Write-Output ("ACM_STAGE background-policy-install elapsed={0:F1}s policy={1}" -f $installTimer.Elapsed.TotalSeconds,$policyId)

$result=[ordered]@{policy_id=$policyId;rule_type='Background Application Bundle';file_path=$null;sha256=$null;publisher=$null;product_name=$null;file_version=$null;requested_files=$fragments.Count;policy_files=$fragments.Count;expanded_files=0}
if($Json){ $result | ConvertTo-Json -Compress } else { $result }
