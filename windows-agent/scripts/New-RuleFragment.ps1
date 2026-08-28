param(
    [Parameter(Mandatory=$true)][ValidateSet('product','hash')][string]$Kind,
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [switch]$Json
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
$resolved=Resolve-CIFilePath $FilePath
if(-not (Test-Path -LiteralPath $resolved -PathType Leaf)){ throw "Rule-fragment source file does not exist: $FilePath" }
$timer=[Diagnostics.Stopwatch]::StartNew()
$rules=@()
if($Kind -eq 'product') { $rules += New-CIPolicyRule -Level FilePublisher -SpecificFileNameLevel ProductName -Fallback SignedVersion,Publisher,Hash -DriverFilePath $resolved }
else { $rules += New-CIPolicyRule -Level Hash -DriverFilePath $resolved }
if($rules.Count -eq 0){ throw "No $Kind rule could be generated for $resolved" }
$dir=Split-Path -Parent $OutputPath
if(-not [string]::IsNullOrWhiteSpace($dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
New-CIPolicy -MultiplePolicyFormat -FilePath $OutputPath -Rules $rules -UserPEs | Out-Null
$timer.Stop()
Write-Output ("ACM_STAGE background-rule-fragment elapsed={0:F1}s kind={1} file={2} rules={3}" -f $timer.Elapsed.TotalSeconds,$Kind,$resolved,$rules.Count)
$result=[pscustomobject]@{ fragment_xml_path=$OutputPath; rule_count=$rules.Count; kind=$Kind; elapsed_seconds=[Math]::Round($timer.Elapsed.TotalSeconds,1) }
if($Json){ $result | ConvertTo-Json -Depth 6 -Compress } else { $result }
