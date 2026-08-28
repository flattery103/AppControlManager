param(
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string]$Name,
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
Ensure-Directories
$state=Read-State
if(!$state.base_policy_id){ throw 'Base policy has not been created.' }
$resolved=Resolve-CIFilePath $FilePath
if(-not (Test-Path -LiteralPath $resolved -PathType Leaf)){ throw "Primary approval file does not exist: $FilePath" }
$meta=Get-FileMetadata $resolved
$timer=[Diagnostics.Stopwatch]::StartNew()
$rules=@()
$mode='hash'
if(-not [string]::IsNullOrWhiteSpace([string]$meta.publisher) -and
   (Test-AppGuardProductFamilyCandidate ([string]$meta.product_name) ([string]$meta.publisher))) {
    try {
        $rules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved
        $mode='product'
    } catch {
        $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved
        $mode='filepublisher'
    }
} else {
    try {
        $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved
        $mode='filepublisher'
    } catch {
        $rules += New-CIPolicyRule -Level Hash -DriverFilePath $resolved
        $mode='hash'
    }
}
if($rules.Count -eq 0){ throw 'No primary App Control rule could be generated.' }
$timer.Stop()
Write-Output ("ACM_STAGE primary-rule-generation elapsed={0:F1}s files=1 file={1} mode={2} rules={3}" -f $timer.Elapsed.TotalSeconds,$resolved,$mode,$rules.Count)
$stamp=Get-Date -Format 'yyyyMMdd-HHmmssfff'
$xml=Join-Path $script:PolicyDir ("Primary-$stamp.xml")
New-CIPolicy -MultiplePolicyFormat -FilePath $xml -Rules $rules -UserPEs | Out-Null
Set-CIPolicyIdInfo -FilePath $xml -PolicyName $Name -ResetPolicyID | Out-Null
Set-CIPolicyIdInfo -FilePath $xml -SupplementsBasePolicyID ([guid]$state.base_policy_id) | Out-Null
Set-CIPolicyVersion -FilePath $xml -Version '1.0.0.0'
$id=Get-CIPolicyGuid $xml
$cip=Join-Path $script:PolicyDir ($id + '.cip')
ConvertFrom-CIPolicy $xml $cip | Out-Null
$install=[Diagnostics.Stopwatch]::StartNew()
CiTool.exe --update-policy $cip -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool policy update failed with exit code $LASTEXITCODE" }
CiTool.exe --refresh -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE" }
$install.Stop()
Write-Output ("ACM_STAGE primary-policy-install elapsed={0:F1}s policy={1}" -f $install.Elapsed.TotalSeconds,$id)
$result=[pscustomobject]@{
    policy_id=$id
    rule_type=(Get-SupplementalRuleType $xml)
    file_path=$meta.file_path
    sha256=$meta.sha256
    publisher=$meta.publisher
    product_name=$meta.product_name
    file_version=$meta.file_version
    requested_files=1
    policy_files=1
    expanded_files=0
    primary_rule_mode=$mode
    xml_path=$xml
    cip_path=$cip
}
if($Json){ $result | ConvertTo-Json -Depth 8 -Compress } else { $result }
