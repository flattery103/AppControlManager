param([switch]$Save)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Common.ps1"
$state=Read-State
if (!$state.learning_started) { throw 'Learning mode has not been started.' }
$start=[datetime]::Parse($state.learning_started).ToLocalTime()
$events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3076; StartTime=$start} -ErrorAction SilentlyContinue)
$seen=@{}
foreach($ev in $events) {
    $data=Get-CIEventData $ev
    $rawPath=Get-CIEventValue $data @('File Name','FileName')
    $path=Resolve-CIFilePath $rawPath
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    if (!$seen.ContainsKey($path)) {
        $meta=Get-FileMetadata $path
        $seen[$path]=[pscustomobject]@{
            file_path=$path
            sha256=$meta.sha256
            publisher=$meta.publisher
            product_name=$meta.product_name
            file_version=$meta.file_version
            first_seen=$ev.TimeCreated.ToUniversalTime().ToString('o')
            record_id=$ev.RecordId
        }
    }
}
$result=@($seen.Values | Sort-Object file_path)
if($Save) { ConvertTo-Json -InputObject $result -Depth 6 | Set-Content (Join-Path $script:Root 'learned.json') -Encoding UTF8 }
$result
