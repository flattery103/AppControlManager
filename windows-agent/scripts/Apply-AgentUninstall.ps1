$ErrorActionPreference='Stop'
$programData='C:\ProgramData\AppControlManager'
$programFiles='C:\Program Files\AppControlManager'
$configPath=Join-Path $programData 'config.json'
$self=$MyInvocation.MyCommand.Path

function Send-OffboardResult([bool]$Success,[string]$Result) {
    if(-not (Test-Path -LiteralPath $configPath)){ return }
    try {
        $cfg=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        if(-not $cfg.server_url -or -not $cfg.device_id -or -not $cfg.device_key){ return }
        $headers=@{'X-Device-ID'=[string]$cfg.device_id;'X-Device-Key'=[string]$cfg.device_key}
        $body=@{success=$Success;result=$Result}|ConvertTo-Json -Compress
        Invoke-RestMethod -Method Post -Uri (([string]$cfg.server_url).TrimEnd('/') + '/api/offboard-complete') -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 15 | Out-Null
    } catch {}
}

function Get-AppControlPolicies {
    $raw=$null
    try { $raw=& CiTool.exe --list-policies -json 2>$null } catch {}
    if(-not $raw){ try { $raw=& CiTool.exe -lp -json 2>$null } catch {} }
    if(-not $raw){ throw 'Could not enumerate Windows App Control policies with CiTool.' }
    try {
        $parsed=($raw -join "`n") | ConvertFrom-Json
        return @($parsed.Policies | Where-Object {
            ([string]$_.FriendlyName -like 'AppControl Manager*') -or
            ([string]$_.FriendlyName -like 'AppGuard POC*')
        })
    } catch { throw 'Could not parse the Windows App Control policy inventory returned by CiTool.' }
}

try {
    # Remove supplemental/deny/update trust policies first and the AppControl Manager base policy last.
    $policies=@(Get-AppControlPolicies | Sort-Object @{Expression={ if(([string]$_.FriendlyName) -like '*Base Policy*'){1}else{0} }})
    foreach($policy in $policies){
        $id=[string]$policy.PolicyID
        if([string]::IsNullOrWhiteSpace($id)){ continue }
        & CiTool.exe --remove-policy $id -json *> $null
        if($LASTEXITCODE -ne 0){ throw "Could not remove Windows App Control policy $id ($($policy.FriendlyName))." }
    }
    & CiTool.exe --refresh -json *> $null
    if($LASTEXITCODE -ne 0){ throw 'Windows App Control policy refresh failed during offboarding.' }
    $remaining=@(Get-AppControlPolicies)
    if($remaining.Count -gt 0){
        throw ('AppControl Manager policies are still installed: ' + (($remaining | ForEach-Object {$_.FriendlyName}) -join ', '))
    }

    Send-OffboardResult $true 'AppControl Manager policies removed successfully. Endpoint agent removal is completing.'

    Stop-Process -Name AppControlManager.Tray -Force -ErrorAction SilentlyContinue
    Stop-Process -Name AppGuard.Tray -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name AppControlManagerTray -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name AppGuardTray -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'AppGuard POC Agent' -Confirm:$false -ErrorAction SilentlyContinue

    Stop-Service AppControlManager -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete AppControlManager | Out-Null
    Stop-Service AppGuardPOC -Force -ErrorAction SilentlyContinue
    sc.exe delete AppGuardPOC | Out-Null
    Start-Sleep -Seconds 2

    for($i=0;$i -lt 5;$i++){
        Remove-Item -LiteralPath $programFiles -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction SilentlyContinue
        if((-not (Test-Path -LiteralPath $programFiles)) -and (-not (Test-Path -LiteralPath $programData))){ break }
        Start-Sleep -Seconds 2
    }

    # The helper runs from TEMP so it can remove the installed product directories first.
    Start-Process -FilePath "$env:ComSpec" -ArgumentList '/c',("ping 127.0.0.1 -n 3 >nul & del /f /q `"$self`"") -WindowStyle Hidden -ErrorAction SilentlyContinue
} catch {
    $message=$_.Exception.Message
    Send-OffboardResult $false $message
    exit 1
}
