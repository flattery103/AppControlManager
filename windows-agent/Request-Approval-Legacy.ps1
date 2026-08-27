param(
    [Parameter(Mandatory=$true)][string]$FilePath,
    [string]$Reason=''
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
$resolved=(Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
$meta=Get-FileMetadata $resolved
$body=@{ file_path=$meta.file_path; sha256=$meta.sha256; publisher=$meta.publisher; product_name=$meta.product_name; file_version=$meta.file_version; reason=$Reason }
$r=Invoke-AgentApi -Method Post -Path '/api/requests' -Body $body
if($r.already_approved) {
    Write-Host "Already approved on this device by policy $($r.policy_id) ($($r.rule_type))." -ForegroundColor Green
} elseif($r.duplicate) {
    Write-Host "Approval request $($r.request_id) already exists and is $($r.status)." -ForegroundColor Yellow
} else {
    Write-Host "Approval request $($r.request_id) submitted for $resolved" -ForegroundColor Green
}
