param(
    [Parameter(Mandatory=$true)][ValidateSet('product','hash')][string]$Operation,
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
$resolved=Resolve-CIFilePath $FilePath
if(-not (Test-Path -LiteralPath $resolved -PathType Leaf)){ throw "Rule-fragment source file does not exist: $FilePath" }
$jobRoot=[IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\')+'\'
$resolved=[IO.Path]::GetFullPath($resolved)
$fixedOutput=[IO.Path]::GetFullPath($OutputPath)
if(-not $resolved.StartsWith($jobRoot,[StringComparison]::OrdinalIgnoreCase)){ throw 'Rule-fragment input escaped the worker job directory.' }
if(-not $fixedOutput.StartsWith($jobRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $fixedOutput) -ne 'fragment.xml'){ throw 'Rule-fragment output is not the fixed worker output.' }
$OutputPath=$fixedOutput
$timer=[Diagnostics.Stopwatch]::StartNew()
$rules=@()
if($Operation -eq 'product') { $rules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved }
else { $rules += New-CIPolicyRule -Level Hash -DriverFilePath $resolved }
if($rules.Count -eq 0){ throw "No $Operation rule could be generated for $resolved" }
$dir=Split-Path -Parent $fixedOutput
if(-not [string]::IsNullOrWhiteSpace($dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
New-CIPolicy -MultiplePolicyFormat -FilePath $OutputPath -Rules $rules -UserPEs | Out-Null
$timer.Stop()
Write-Output ("ACM_STAGE background-rule-fragment elapsed={0:F1}s operation={1} file={2} rules={3}" -f $timer.Elapsed.TotalSeconds,$Operation,$resolved,$rules.Count)
$meta=Get-FileMetadata $resolved
$result=[pscustomobject]@{
    operation=$Operation
    rule_count=$rules.Count
    rule_mode=$Operation
    elapsed_seconds=[Math]::Round($timer.Elapsed.TotalSeconds,1)
    file_path=$meta.file_path
    sha256=$meta.sha256
    publisher=$meta.publisher
    product_name=$meta.product_name
    file_version=$meta.file_version
}
if($Json){ $result | ConvertTo-Json -Depth 6 -Compress } else { $result }
