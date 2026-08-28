param(
    [Parameter(Mandatory=$true)][object[]]$LearnedApplications,
    [string]$Name='AppControl Manager Learned Baseline'
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state=Read-State
if (!$state.base_policy_id) { throw 'Base policy has not been created.' }

# Learning already collected hash, signer, product and version metadata once in
# Get-LearnedApplications.ps1. Reuse that snapshot here rather than re-reading signatures for
# every executable before ConfigCI runs.
$classifyTimer=[System.Diagnostics.Stopwatch]::StartNew()
$seenPaths=@{}
$publisherProductGroups=@{}
$individualSignedFiles=New-Object System.Collections.Generic.List[string]
$hashFiles=New-Object System.Collections.Generic.List[string]
$existingCount=0
$signedCount=0
$familyFileCount=0
$missingCount=0

foreach($item in @($LearnedApplications)) {
    $rawPath=[string]$item.file_path
    if([string]::IsNullOrWhiteSpace($rawPath)) { continue }
    $resolved=Resolve-CIFilePath $rawPath
    if(-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { $missingCount++; continue }
    $pathKey=$resolved.ToLowerInvariant()
    if($seenPaths.ContainsKey($pathKey)) { continue }
    $seenPaths[$pathKey]=$true
    $existingCount++

    $publisher=([string]$item.publisher).Trim()
    $product=([string]$item.product_name).Trim()
    $versionText=([string]$item.file_version).Trim()
    if([string]::IsNullOrWhiteSpace($publisher)) {
        $hashFiles.Add($resolved)
        continue
    }

    $signedCount++
    $parsedVersion=$null
    $hasParsedVersion=(-not [string]::IsNullOrWhiteSpace($versionText)) -and [version]::TryParse($versionText,[ref]$parsedVersion)
    $useProductFamily=(Test-AppGuardProductFamilyCandidate $product $publisher) -and $hasParsedVersion
    if(-not $useProductFamily) {
        # Generic/runtime product names and files without a trustworthy numeric version remain
        # conservative per-file FilePublisher rules rather than becoming publisher-wide allows.
        $individualSignedFiles.Add($resolved)
        continue
    }

    $groupKey=($publisher.ToLowerInvariant() + '|' + $product.ToLowerInvariant())
    if(-not $publisherProductGroups.ContainsKey($groupKey)) {
        $publisherProductGroups[$groupKey]=[pscustomobject]@{
            publisher=$publisher
            product_name=$product
            file_path=$resolved
            parsed_version=$parsedVersion
            file_count=1
        }
    } else {
        $group=$publisherProductGroups[$groupKey]
        $group.file_count=[int]$group.file_count + 1
        # FilePublisher rules use the representative file's version as the minimum version.
        # Pick the lowest learned version so every version actually observed during Learning is
        # covered while still allowing future versions of that signer/product family.
        if($parsedVersion -lt $group.parsed_version) {
            $group.file_path=$resolved
            $group.parsed_version=$parsedVersion
        }
    }
    $familyFileCount++
}

$familyRepresentatives=@($publisherProductGroups.Values | ForEach-Object { [string]$_.file_path })
$classifyTimer.Stop()
Write-Output ("ACM_STAGE learned-classification elapsed={0:F1}s learned={1} existing={2} signed={3} unsigned={4} publisherProductGroups={5} familyFiles={6} individualSigned={7} hashFiles={8} missing={9}" -f $classifyTimer.Elapsed.TotalSeconds,$LearnedApplications.Count,$existingCount,$signedCount,$hashFiles.Count,$publisherProductGroups.Count,$familyFileCount,$individualSignedFiles.Count,$hashFiles.Count,$missingCount)

if($existingCount -eq 0) { throw 'No learned application files currently exist on this device.' }

$ruleTimer=[System.Diagnostics.Stopwatch]::StartNew()
$rules=@()
$familyRuleCount=0
$individualRuleCount=0
$hashRuleCount=0

if($familyRepresentatives.Count -gt 0) {
    $timer=[System.Diagnostics.Stopwatch]::StartNew()
    $familyRules=@()
    try {
        # One representative per signer + ProductName family, selected at the lowest learned
        # version, collapses many learned binaries into a small and update-friendly rule set.
        $familyRules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath ([string[]]$familyRepresentatives)
    } catch {
        # Keep one odd product from invalidating the entire learned baseline. Product-family
        # failures fall back conservatively to exact FilePublisher/hash coverage for that file.
        foreach($p in $familyRepresentatives) {
            try { $familyRules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $p }
            catch {
                try { $familyRules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $p }
                catch { $familyRules += New-CIPolicyRule -Level Hash -DriverFilePath $p }
            }
        }
    }
    $rules += $familyRules
    $familyRuleCount=$familyRules.Count
    $timer.Stop()
    Write-Output ("ACM_STAGE learned-family-rules elapsed={0:F1}s publisherProductGroups={1} representatives={2} rules={3}" -f $timer.Elapsed.TotalSeconds,$publisherProductGroups.Count,$familyRepresentatives.Count,$familyRuleCount)
}

if($individualSignedFiles.Count -gt 0) {
    $timer=[System.Diagnostics.Stopwatch]::StartNew()
    $individualRules=@()
    try {
        $individualRules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath ([string[]]$individualSignedFiles.ToArray())
    } catch {
        foreach($p in $individualSignedFiles) {
            try { $individualRules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $p }
            catch { $individualRules += New-CIPolicyRule -Level Hash -DriverFilePath $p }
        }
    }
    $rules += $individualRules
    $individualRuleCount=$individualRules.Count
    $timer.Stop()
    Write-Output ("ACM_STAGE learned-individual-rules elapsed={0:F1}s files={1} rules={2}" -f $timer.Elapsed.TotalSeconds,$individualSignedFiles.Count,$individualRuleCount)
}

if($hashFiles.Count -gt 0) {
    $timer=[System.Diagnostics.Stopwatch]::StartNew()
    $generatedHashRules=@()
    try {
        $generatedHashRules += New-CIPolicyRule -Level Hash -DriverFilePath ([string[]]$hashFiles.ToArray())
    } catch {
        foreach($p in $hashFiles) { $generatedHashRules += New-CIPolicyRule -Level Hash -DriverFilePath $p }
    }
    $rules += $generatedHashRules
    $hashRuleCount=$generatedHashRules.Count
    $timer.Stop()
    Write-Output ("ACM_STAGE learned-hash-rules elapsed={0:F1}s files={1} rules={2}" -f $timer.Elapsed.TotalSeconds,$hashFiles.Count,$hashRuleCount)
}

if($rules.Count -eq 0) { throw 'No App Control allow rules could be generated for the learned baseline.' }
$ruleTimer.Stop()
Write-Output ("ACM_STAGE rule-generation elapsed={0:F1}s files={1} publisherProductGroups={2} individualPublisherRules={3} hashRules={4} rules={5}" -f $ruleTimer.Elapsed.TotalSeconds,$existingCount,$publisherProductGroups.Count,$individualRuleCount,$hashRuleCount,$rules.Count)

$xmlTimer=[System.Diagnostics.Stopwatch]::StartNew()
$stamp=Get-Date -Format 'yyyyMMdd-HHmmssfff'
$xml=Join-Path $script:PolicyDir ("Supplemental-$stamp.xml")
New-CIPolicy -MultiplePolicyFormat -FilePath $xml -Rules $rules -UserPEs | Out-Null
Set-CIPolicyIdInfo -FilePath $xml -PolicyName $Name -ResetPolicyID | Out-Null
Set-CIPolicyIdInfo -FilePath $xml -SupplementsBasePolicyID ([guid]$state.base_policy_id) | Out-Null
Set-CIPolicyVersion -FilePath $xml -Version '1.0.0.0'
$id=Get-CIPolicyGuid $xml
$xmlTimer.Stop()
Write-Output ("ACM_STAGE policy-xml elapsed={0:F1}s policy={1}" -f $xmlTimer.Elapsed.TotalSeconds,$id)

$convertTimer=[System.Diagnostics.Stopwatch]::StartNew()
$cip=Join-Path $script:PolicyDir ($id + '.cip')
ConvertFrom-CIPolicy $xml $cip | Out-Null
$convertTimer.Stop()
Write-Output ("ACM_STAGE policy-convert elapsed={0:F1}s policy={1}" -f $convertTimer.Elapsed.TotalSeconds,$id)

$installTimer=[System.Diagnostics.Stopwatch]::StartNew()
CiTool.exe --update-policy $cip -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool policy update failed with exit code $LASTEXITCODE" }
CiTool.exe --refresh -json | Out-Null
if($LASTEXITCODE -ne 0){ throw "CiTool refresh failed with exit code $LASTEXITCODE" }
$installTimer.Stop()
Write-Output ("ACM_STAGE policy-install elapsed={0:F1}s policy={1}" -f $installTimer.Elapsed.TotalSeconds,$id)
Write-Output $id
