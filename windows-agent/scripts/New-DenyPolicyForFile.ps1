param(
    [Parameter(Mandatory=$true)][string[]]$FilePath,
    [string]$Name='AppControl Manager Deny Policy',
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
Ensure-Directories
$existing=@($FilePath | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -Unique)
if($existing.Count -eq 0) { throw 'None of the requested files currently exist on this device.' }
$allowAll=Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'
if(!(Test-Path -LiteralPath $allowAll)) { throw "Windows AllowAll App Control template was not found at $allowAll" }

$rules=@()
$familyKeys=@{}
$familyRuleCount=0
$fileRuleCount=0
foreach($file in $existing) {
    $meta=Get-FileMetadata $file
    $useFamily=Test-AppGuardProductFamilyCandidate ([string]$meta.product_name) ([string]$meta.publisher)
    if($useFamily) {
        $key=(([string]$meta.publisher).Trim().ToLowerInvariant() + '|' + ([string]$meta.product_name).Trim().ToLowerInvariant())
        if($familyKeys.ContainsKey($key)) { continue }
        try {
            $rules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $file -Deny
            $familyKeys[$key]=$true
            $familyRuleCount++
            continue
        } catch {
            # Fall through to conservative per-file deny.
        }
    }
    try { $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $file -Deny; $fileRuleCount++ }
    catch { $rules += New-CIPolicyRule -Level Hash -DriverFilePath $file -Deny; $fileRuleCount++ }
}
if($rules.Count -eq 0) { throw 'No App Control deny rules could be generated.' }

$stamp=Get-Date -Format 'yyyyMMdd-HHmmssfff'
$xml=Join-Path $script:PolicyDir ("Deny-$stamp.xml")
$workingAllowAll=Join-Path $script:PolicyDir ("AllowAll-Working-$stamp.xml")
# Merge-CIPolicy may update the policy passed in through -PolicyPaths. The Windows example
# policy lives under C:\Windows and is read-only to this workflow, so always work from a copy
# in AppControl Manager's writable policy directory. Never modify Microsoft's template in place.
Copy-Item -LiteralPath $allowAll -Destination $workingAllowAll -Force
try {
    Merge-CIPolicy -PolicyPaths $workingAllowAll -OutputFilePath $xml -Rules $rules | Out-Null
}
finally {
    Remove-Item -LiteralPath $workingAllowAll -Force -ErrorAction SilentlyContinue
}
# ResetPolicyID converts the template to multiple-policy format and gives this deny policy a unique ID.
Set-CIPolicyIdInfo -FilePath $xml -PolicyName $Name -ResetPolicyID | Out-Null
try { Set-RuleOption -FilePath $xml -Option 3 -Delete | Out-Null } catch {}
try { Set-RuleOption -FilePath $xml -Option 11 | Out-Null } catch {}
try { Set-RuleOption -FilePath $xml -Option 16 | Out-Null } catch {}
Set-CIPolicyVersion -FilePath $xml -Version '1.0.0.0'
$id=Get-CIPolicyGuid $xml
$cip=Join-Path $script:PolicyDir ($id + '.cip')
ConvertFrom-CIPolicy $xml $cip | Out-Null

$updateOutput = & CiTool.exe --update-policy $cip -json 2>&1
if($LASTEXITCODE -ne 0){ throw "CiTool policy update failed with exit code $LASTEXITCODE. $($updateOutput -join ' ')" }
$refreshOutput = & CiTool.exe --refresh -json 2>&1
if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE. $($refreshOutput -join ' ')" }

$meta=Get-FileMetadata $existing[0]
$detected=Get-DenyRuleType $xml
$ruleType=if($familyRuleCount -gt 0){'FilePublisher Product Family Deny'}else{$detected}
$result=[pscustomobject]@{
    policy_id=$id
    rule_type=$ruleType
    file_path=$meta.file_path
    sha256=$meta.sha256
    publisher=$meta.publisher
    product_name=$meta.product_name
    file_version=$meta.file_version
    family_rules=$familyRuleCount
    file_rules=$fileRuleCount
    xml_path=$xml
    cip_path=$cip
}
if($Json) { $result | ConvertTo-Json -Depth 8 -Compress } else { $result }
