param(
    [Parameter(Mandatory=$true)][ValidateSet('primary_allow','deny_policy')][string]$Operation,
    [Parameter(Mandatory=$true)][string]$XmlPath,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][ValidateSet('product','product_family','filepublisher','hash')][string]$RuleMode,
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
. "$PSScriptRoot\GeneratedPolicyValidation.ps1"
Assert-Administrator
Ensure-Directories

$policyRoot=[IO.Path]::GetFullPath($script:PolicyDir).TrimEnd('\')+'\'
$xml=[IO.Path]::GetFullPath($XmlPath)
if(-not $xml.StartsWith($policyRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($xml) -ne '.xml') {
    throw 'Generated policy XML escaped the protected policy directory.'
}
if(-not (Test-Path -LiteralPath $xml -PathType Leaf)){ throw "Generated policy XML does not exist: $xml" }
try {
    [xml]$document=Get-Content -LiteralPath $xml -Raw -Encoding UTF8
} catch {
    throw "Generated policy XML is invalid: $($_.Exception.Message)"
}
if($null -eq $document.DocumentElement -or
   $document.DocumentElement.LocalName -ne 'SiPolicy' -or
   $document.DocumentElement.NamespaceURI -ne 'urn:schemas-microsoft-com:sipolicy') {
    throw 'Generated XML is not a Windows App Control policy.'
}

$postProcess=[Diagnostics.Stopwatch]::StartNew()
if($Operation -eq 'deny_policy') {
    # The worker contributes deny rule material only. LocalSystem owns the AllowAll merge,
    # final policy identity, required deny options, conversion, and installation.
    $allowAll=Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'
    if(-not (Test-Path -LiteralPath $allowAll -PathType Leaf)){ throw "Windows AllowAll App Control template was not found at $allowAll" }
    $mergeId=[guid]::NewGuid().ToString('N')
    $workingAllowAll=Join-Path $script:PolicyDir ("AllowAll-Working-$mergeId.xml")
    $mergedXml=Join-Path $script:PolicyDir ("Deny-Merged-$mergeId.xml")
    Copy-Item -LiteralPath $allowAll -Destination $workingAllowAll -Force
    try {
        Merge-CIPolicy -PolicyPaths ([string[]]@($workingAllowAll,$xml)) -OutputFilePath $mergedXml | Out-Null
        if(-not (Test-Path -LiteralPath $mergedXml -PathType Leaf)){ throw 'LocalSystem deny merge did not produce policy XML.' }
        Move-Item -LiteralPath $mergedXml -Destination $xml -Force
    } finally {
        Remove-Item -LiteralPath $workingAllowAll -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $mergedXml -Force -ErrorAction SilentlyContinue
    }
}
Set-CIPolicyIdInfo -FilePath $xml -PolicyName $Name -ResetPolicyID | Out-Null
if($Operation -eq 'primary_allow') {
    $state=Read-State
    if(!$state.base_policy_id){ throw 'Base policy has not been created.' }
    Set-CIPolicyIdInfo -FilePath $xml -SupplementsBasePolicyID ([guid]$state.base_policy_id) | Out-Null
} else {
    Set-RuleOption -FilePath $xml -Option 3 -Delete | Out-Null
    Set-RuleOption -FilePath $xml -Option 11 | Out-Null
    Set-RuleOption -FilePath $xml -Option 16 | Out-Null
}
Set-CIPolicyVersion -FilePath $xml -Version '1.0.0.0'
$policyId=Get-CIPolicyGuid $xml
$postProcess.Stop()
Write-Output ("ACM_STAGE generated-policy-postprocess elapsed={0:F1}s operation={1} mode={2} policy={3}" -f $postProcess.Elapsed.TotalSeconds,$Operation,$RuleMode,$policyId)

$cip=Join-Path $script:PolicyDir ($policyId.ToUpperInvariant()+'.cip')
$install=[Diagnostics.Stopwatch]::StartNew()
ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cip | Out-Null
$updateOutput=& CiTool.exe --update-policy $cip -json 2>&1
if($LASTEXITCODE -ne 0){ throw "CiTool policy update failed with exit code $LASTEXITCODE. $($updateOutput -join ' ')" }
$refreshOutput=& CiTool.exe --refresh -json 2>&1
if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE. $($refreshOutput -join ' ')" }

$listingOutput=& CiTool.exe -lp -json 2>&1
if($LASTEXITCODE -ne 0){ throw "CiTool list-policies failed with exit code $LASTEXITCODE. $($listingOutput -join ' ')" }
$listingJson=($listingOutput -join [Environment]::NewLine) | ConvertFrom-Json
$listing=@($listingJson.Policies)
$installed=Assert-InstalledGeneratedPolicy -Policies $listing -PolicyId $policyId
$install.Stop()
Write-Output ("ACM_STAGE generated-policy-install elapsed={0:F1}s operation={1} policy={2}" -f $install.Elapsed.TotalSeconds,$Operation,$policyId)

$ruleType=if($Operation -eq 'primary_allow') {
    Get-SupplementalRuleType $xml
} elseif($RuleMode -eq 'product_family') {
    'FilePublisher Product Family Deny'
} else {
    Get-DenyRuleType $xml
}
$result=[ordered]@{
    policy_id=$policyId
    rule_type=$ruleType
    xml_path=$xml
    cip_path=$cip
}
if($Json){ $result | ConvertTo-Json -Depth 6 -Compress } else { $result }
