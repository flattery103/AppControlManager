param(
    [string[]]$FilePath,
    [string]$FileListPath,
    [string]$Name='AppControl Manager Supplemental',
    [switch]$AsObject,
    [switch]$Json,
    [switch]$AlreadyExpanded
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state=Read-State
if (!$state.base_policy_id) { throw 'Base policy has not been created.' }

$inputPaths=@()
if(-not [string]::IsNullOrWhiteSpace($FileListPath)) {
    if(-not (Test-Path -LiteralPath $FileListPath -PathType Leaf)) { throw "Policy file-list input does not exist: $FileListPath" }
    $fileListJson=Get-Content -LiteralPath $FileListPath -Raw -Encoding UTF8
    if(-not [string]::IsNullOrWhiteSpace($fileListJson)) { $inputPaths=[string[]](ConvertFrom-Json -InputObject $fileListJson) }
} elseif($null -ne $FilePath) {
    $inputPaths=@($FilePath)
}
if($inputPaths.Count -eq 0) { throw 'No requested file paths were supplied.' }
$requested=@($inputPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -Unique)
if($requested.Count -eq 0) { throw 'None of the requested files currently exist on this device.' }

# If the C# service already expanded a protected-install application bundle, use the supplied
# list directly. Re-expanding every supplied file caused the same application tree to be
# recursively scanned and signature-checked many times (Chrome could take ~12 minutes).
# Direct/manual PowerShell callers can omit -AlreadyExpanded and retain legacy expansion.
$policyFiles = New-Object System.Collections.Generic.List[string]
$seenFiles=@{}
if($AlreadyExpanded) {
    foreach($p in $requested) {
        $resolved=Resolve-CIFilePath $p
        if(-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { continue }
        $key=$resolved.ToLowerInvariant()
        if($seenFiles.ContainsKey($key)) { continue }
        $seenFiles[$key]=$true
        $policyFiles.Add($resolved)
    }
} else {
    # Legacy/direct-helper path: discover same-publisher components for a single protected
    # Program Files application. The C# service normally performs this expansion now.
    foreach($p in $requested) {
        $resolved=Resolve-CIFilePath $p
        $meta=Get-FileMetadata $resolved
        $bundle=@($resolved)
        if(-not [string]::IsNullOrWhiteSpace([string]$meta.publisher) -and (Test-AppGuardProtectedInstallPath $resolved)) {
            $bundle=@(Get-AppGuardProtectedPublisherBundleFiles -PrimaryPath $resolved -Publisher ([string]$meta.publisher))
        }
        foreach($candidate in $bundle) {
            if(-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            $key=$candidate.ToLowerInvariant()
            if($seenFiles.ContainsKey($key)) { continue }
            $seenFiles[$key]=$true
            $policyFiles.Add($candidate)
        }
    }
}
if($policyFiles.Count -eq 0) { throw 'No files were available for App Control rule generation.' }

$policyFileArray=@($policyFiles | ForEach-Object { [string]$_ })
$ruleTimer=[System.Diagnostics.Stopwatch]::StartNew()
$rules=@()
try {
    # Generate real per-binary FilePublisher rules in one pass. This is more reliable on current
    # ConfigCI builds than relying on SpecificFileNameLevel=ProductName for FilePublisher rules,
    # while still allowing future versions of those filenames from the same signer.
    $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $policyFileArray
} catch {
    # Fall back to individual generation so one unusual binary cannot prevent the rest of the
    # application bundle from being approved.
    foreach($p in $policyFiles) {
        try { $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $p }
        catch { $rules += New-CIPolicyRule -Level Hash -DriverFilePath $p }
    }
}
if($rules.Count -eq 0) { throw 'No App Control allow rules could be generated.' }
$ruleTimer.Stop()
Write-Output ("ACM_STAGE rule-generation elapsed={0:F1}s files={1} rules={2}" -f $ruleTimer.Elapsed.TotalSeconds,$policyFiles.Count,$rules.Count)

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
if($AsObject -or $Json) {
    $meta=Get-FileMetadata $requested[0]
    $detected=Get-SupplementalRuleType $xml
    $expandedCount=[Math]::Max(($policyFiles.Count - $requested.Count),0)
    $ruleType = if($expandedCount -gt 0) { 'FilePublisher Application Bundle' } else { $detected }
    $result=[pscustomobject]@{
        policy_id=$id
        rule_type=$ruleType
        file_path=$meta.file_path
        sha256=$meta.sha256
        publisher=$meta.publisher
        product_name=$meta.product_name
        file_version=$meta.file_version
        requested_files=$requested.Count
        policy_files=$policyFiles.Count
        expanded_files=$expandedCount
        xml_path=$xml
        cip_path=$cip
    }
    if($Json) { $result | ConvertTo-Json -Depth 8 -Compress } else { $result }
} else {
    Write-Output $id
}
