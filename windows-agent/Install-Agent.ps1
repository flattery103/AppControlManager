param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$EnrollmentToken
)
$ErrorActionPreference='Stop'
$programData='C:\ProgramData\AppControlManager'
$programFiles='C:\Program Files\AppControlManager'
$publish=Join-Path $PSScriptRoot 'publish'
$serviceExe=Join-Path $publish 'Service\AppControlManager.Service.exe'
$trayExe=Join-Path $publish 'Tray\AppControlManager.Tray.exe'
if(!(Test-Path $serviceExe)){ throw 'Published binaries not found. Run .\Build.ps1 first or use the GitHub Actions artifact.' }
if(!(Test-Path $trayExe)){ throw 'Published tray binary not found. Run .\Build.ps1 first or use the GitHub Actions artifact.' }
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ throw 'Run this installer as Administrator.' }
New-Item -ItemType Directory -Path $programData,$programFiles,"$programFiles\Scripts","$programData\Policies" -Force | Out-Null

if(!(Test-Path "$programData\config.json")) {
    $body=@{hostname=$env:COMPUTERNAME;os_version=(Get-CimInstance Win32_OperatingSystem).Version;enrollment_token=$EnrollmentToken}
    $enrolled=Invoke-RestMethod -Method Post -Uri ($ServerUrl.TrimEnd('/') + '/api/enroll') -ContentType 'application/json' -Body ($body|ConvertTo-Json)
    @{server_url=$ServerUrl.TrimEnd('/');device_id=$enrolled.device_id;device_key=$enrolled.device_key}|ConvertTo-Json|Set-Content "$programData\config.json" -Encoding UTF8
}

Copy-Item "$PSScriptRoot\scripts\*.ps1" "$programFiles\Scripts\" -Force
Copy-Item "$PSScriptRoot\scripts\*.ps1" "$programData\" -Force
Copy-Item $serviceExe "$programFiles\AppControlManager.Service.exe" -Force
Copy-Item $trayExe "$programFiles\AppControlManager.Tray.exe" -Force

$existing=Get-Service -Name AppControlManager -ErrorAction SilentlyContinue
if($existing){ Stop-Service AppControlManager -Force -ErrorAction SilentlyContinue; sc.exe delete AppControlManager | Out-Null; Start-Sleep 1 }
New-Service -Name AppControlManager -BinaryPathName '"C:\Program Files\AppControlManager\AppControlManager.Service.exe"' -DisplayName 'AppControl Manager Agent' -Description 'AppControl Manager application-control agent' -StartupType Automatic | Out-Null
Start-Service AppControlManager
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'AppControlManagerTray' -PropertyType String -Value '"C:\Program Files\AppControlManager\AppControlManager.Tray.exe"' -Force | Out-Null
Start-Process "$programFiles\AppControlManager.Tray.exe" -ErrorAction SilentlyContinue
Write-Host 'AppControl Manager 0.13.0 service and tray installed.' -ForegroundColor Green
Write-Host 'No Windows App Control policy was enabled by this installer.' -ForegroundColor Yellow
