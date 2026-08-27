$ErrorActionPreference='Stop'
$trayExe='C:\Program Files\AppControlManager\AppControlManager.Tray.exe'
$taskPrefix='AppControlManager Tray Recovery'

if(Get-Process -Name 'AppControlManager.Tray' -ErrorAction SilentlyContinue){
    Write-Output 'Tray is already running.'
    exit 0
}
if(!(Test-Path -LiteralPath $trayExe)){
    throw "Tray executable not found: $trayExe"
}

# Win32_ComputerSystem.UserName only represents the console user and can be empty for
# RDP/remote sessions. Explorer processes give us the actual interactive shell users.
$users=@()
try {
    $users=@(Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserName) } |
        Select-Object -ExpandProperty UserName -Unique)
} catch {}

# Fallback for systems where IncludeUserName is unavailable but a console session exists.
if($users.Count -eq 0){
    try {
        $consoleUser=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if(-not [string]::IsNullOrWhiteSpace($consoleUser)){ $users=@($consoleUser) }
    } catch {}
}

if($users.Count -eq 0){
    Write-Output 'No interactive Windows user session is currently available; tray will start at the next user logon.'
    exit 0
}

$errors=@()
foreach($user in $users){
    $safe=($user -replace '[^A-Za-z0-9_.-]','_')
    $taskName="$taskPrefix $safe"
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action=New-ScheduledTaskAction -Execute $trayExe
        $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
        $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName

        $deadline=(Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 500
            if(Get-Process -Name 'AppControlManager.Tray' -ErrorAction SilentlyContinue){
                Write-Output "Tray started in an interactive session for $user."
                exit 0
            }
        } while((Get-Date) -lt $deadline)

        $info=Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $result=if($info){ $info.LastTaskResult }else{ 'unknown' }
        $errors += "$user (task result $result)"
    }
    catch {
        $errors += "$user ($($_.Exception.Message))"
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

throw "Unable to start AppControlManager.Tray.exe in the interactive user session(s): $($errors -join '; ')"
