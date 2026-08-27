$ErrorActionPreference='SilentlyContinue'
Stop-Service AppControlManager -Force
sc.exe delete AppControlManager | Out-Null
Stop-Service AppGuardPOC -Force
sc.exe delete AppGuardPOC | Out-Null
Stop-Process -Name AppControlManager.Tray -Force
Stop-Process -Name AppGuard.Tray -Force
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name AppControlManagerTray
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name AppGuardTray
Write-Host 'AppControl Manager service/tray removed. ProgramData and Windows App Control policies were intentionally left in place.' -ForegroundColor Yellow
