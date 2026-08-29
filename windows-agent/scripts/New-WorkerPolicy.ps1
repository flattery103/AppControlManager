param(
    [Parameter(Mandatory=$true)][ValidateSet('primary_allow','deny_policy')][string]$Operation,
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"

$jobRoot=[IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\')+'\'
$resolved=Resolve-CIFilePath $FilePath
if(-not (Test-Path -LiteralPath $resolved -PathType Leaf)){ throw "Worker policy source file does not exist: $FilePath" }
$resolved=[IO.Path]::GetFullPath($resolved)
$fixedOutput=[IO.Path]::GetFullPath($OutputPath)
if(-not $resolved.StartsWith($jobRoot,[StringComparison]::OrdinalIgnoreCase)){ throw 'Worker policy input escaped the job directory.' }
if(-not $fixedOutput.StartsWith($jobRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $fixedOutput) -ne 'policy.xml'){ throw 'Worker policy output is not the fixed job output.' }

$meta=Get-FileMetadata $resolved
$timer=[Diagnostics.Stopwatch]::StartNew()
$rules=@()
$mode='hash'

if($Operation -eq 'primary_allow') {
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
    New-CIPolicy -MultiplePolicyFormat -FilePath $fixedOutput -Rules $rules -UserPEs | Out-Null
} else {
    $useFamily=Test-AppGuardProductFamilyCandidate ([string]$meta.product_name) ([string]$meta.publisher)
    if($useFamily) {
        try {
            $rules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved -Deny
            $mode='product_family'
        } catch {
            # Fall through to conservative per-file deny.
        }
    }
    if($rules.Count -eq 0) {
        try {
            $rules += New-CIPolicyRule -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved -Deny
            $mode='filepublisher'
        } catch {
            $rules += New-CIPolicyRule -Level Hash -DriverFilePath $resolved -Deny
            $mode='hash'
        }
    }
    if($rules.Count -eq 0){ throw 'No App Control deny rules could be generated.' }
    New-CIPolicy -MultiplePolicyFormat -FilePath $fixedOutput -Rules $rules -UserPEs | Out-Null
}

$timer.Stop()
Write-Output ("ACM_STAGE worker-policy-generation elapsed={0:F1}s operation={1} file={2} mode={3} rules={4}" -f $timer.Elapsed.TotalSeconds,$Operation,$resolved,$mode,$rules.Count)
$result=[pscustomobject]@{
    operation=$Operation
    rule_count=$rules.Count
    rule_mode=$mode
    elapsed_seconds=[Math]::Round($timer.Elapsed.TotalSeconds,1)
    file_path=$meta.file_path
    sha256=$meta.sha256
    publisher=$meta.publisher
    product_name=$meta.product_name
    file_version=$meta.file_version
}
if($Json){ $result | ConvertTo-Json -Depth 6 -Compress } else { $result }
