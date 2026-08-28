param(
    [Parameter(Mandatory=$true)][string]$FragmentListPath,
    [string]$Name='AppControl Manager Learned Baseline',
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state=Read-State
if(!$state.base_policy_id){ throw 'Base policy has not been created.' }
if(-not (Test-Path -LiteralPath $FragmentListPath -PathType Leaf)){ throw "Learned fragment list does not exist: $FragmentListPath" }
$raw=Get-Content -LiteralPath $FragmentListPath -Raw -Encoding UTF8
$fragments=[string[]](ConvertFrom-Json -InputObject $raw)
$fragments=@($fragments | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
if($fragments.Count -lt 1){ throw 'No prepared learned rule fragments were supplied.' }
foreach($fragment in $fragments){ if(-not (Test-Path -LiteralPath $fragment -PathType Leaf)){ throw "Prepared learned fragment does not exist: $fragment" } }

$dir=Join-Path $env:ProgramData 'AppControlManager\Policies'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd-HHmmssfff'
$mergedXml=Join-Path $dir "LearnedBaseline-$stamp.xml"
$mergeTimer=[Diagnostics.Stopwatch]::StartNew()
Merge-CIPolicy -PolicyPaths ([string[]]$fragments) -OutputFilePath $mergedXml
Set-CIPolicyIdInfo -FilePath $mergedXml -PolicyName $Name -ResetPolicyID | Out-Null
Set-CIPolicyIdInfo -FilePath $mergedXml -SupplementsBasePolicyID ([guid]$state.base_policy_id) | Out-Null
Set-CIPolicyVersion -FilePath $mergedXml -Version '1.0.0.0'
$policyId=Get-CIPolicyGuid $mergedXml
$mergeTimer.Stop()
Write-Output ("ACM_STAGE learned-baseline-merge elapsed={0:F1}s fragments={1}" -f $mergeTimer.Elapsed.TotalSeconds,$fragments.Count)

$cip=Join-Path $dir ((($policyId -replace '[{}]','').ToUpperInvariant())+'.cip')
$installTimer=[Diagnostics.Stopwatch]::StartNew()
ConvertFrom-CIPolicy -XmlFilePath $mergedXml -BinaryFilePath $cip
CiTool.exe --update-policy $cip -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool update-policy failed with exit code $LASTEXITCODE" }
CiTool.exe --refresh -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE" }
$listing=@((CiTool.exe -lp -json | ConvertFrom-Json).Policies)
$normalized=($policyId -replace '[{}]','').ToLowerInvariant()
$installed=@($listing | Where-Object { (([string]$_.PolicyID) -replace '[{}]','').ToLowerInvariant() -eq $normalized }) | Select-Object -First 1
if($null -eq $installed){ throw "Installed learned baseline $policyId was not returned by CiTool." }
$enforced=$true
if($installed.PSObject.Properties.Name -contains 'IsCurrentlyEnforced'){ $enforced=[bool]$installed.IsCurrentlyEnforced }
$authorized=$true
if($installed.PSObject.Properties.Name -contains 'IsAuthorized'){ $authorized=[bool]$installed.IsAuthorized }
if(-not $enforced -or -not $authorized){ throw "Installed learned baseline $policyId is not enforced/authorized." }
$installTimer.Stop()
Write-Output ("ACM_STAGE learned-baseline-install elapsed={0:F1}s policy={1}" -f $installTimer.Elapsed.TotalSeconds,$policyId)
Write-Output ("Installed learned baseline {0}" -f $policyId)

# The replacement is verified above before any prior learned baseline is removed.
$cleanupTimer=[Diagnostics.Stopwatch]::StartNew()
$removed=0; $failed=0
foreach($policy in $listing){
    $friendly=[string]$policy.FriendlyName
    if([string]::IsNullOrWhiteSpace($friendly) -and ($policy.PSObject.Properties.Name -contains 'Friendly Name')){ $friendly=[string]$policy.'Friendly Name' }
    $candidate=(([string]$policy.PolicyID) -replace '[{}]','').ToLowerInvariant()
    if($friendly -ne 'AppControl Manager Learned Baseline' -or $candidate -eq $normalized){ continue }
    try {
        CiTool.exe --remove-policy ([string]$policy.PolicyID) -json | Out-Null
        if($LASTEXITCODE -ne 0){ throw "CiTool remove-policy failed with exit code $LASTEXITCODE" }
        $removed++
    } catch {
        $failed++
        Write-Warning ("Could not remove stale learned baseline {0}: {1}" -f $policy.PolicyID,$_.Exception.Message)
    }
}
CiTool.exe --refresh -json | Out-Null
$cleanupTimer.Stop()
Write-Output ("ACM_STAGE learned-baseline-cleanup elapsed={0:F1}s removed={1} failed={2}" -f $cleanupTimer.Elapsed.TotalSeconds,$removed,$failed)
Write-Output ("stale learned-baseline policies removed={0} failed={1}" -f $removed,$failed)
$result=[ordered]@{policy_id=$policyId;rule_type='Learned Baseline';fragment_count=$fragments.Count;stale_removed=$removed;stale_failed=$failed}
if($Json){ $result | ConvertTo-Json -Compress } else { $result }
