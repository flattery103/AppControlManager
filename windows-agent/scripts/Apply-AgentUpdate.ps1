param(
    [Parameter(Mandatory=$true)][string]$StagingPath,
    [Parameter(Mandatory=$true)][string]$TargetVersion,
    [Parameter(Mandatory=$true)][string]$CurrentVersion,
    [Parameter(Mandatory=$true)][string]$StatusPath,
    [Parameter(Mandatory=$true)][string]$BackupRoot
)
$ErrorActionPreference='Stop'
$serviceName='AppControlManager'
$ruleWorkerServiceName='AppControlManagerRuleWorker'
$programFiles='C:\Program Files\AppControlManager'
$programData='C:\ProgramData\AppControlManager'
$trayExe=Join-Path $programFiles 'AppControlManager.Tray.exe'

function Read-UpdateStatus {
    try { if(Test-Path -LiteralPath $StatusPath){ return Get-Content -LiteralPath $StatusPath -Raw | ConvertFrom-Json } } catch {}
    return [pscustomobject]@{}
}
function Write-UpdateStatus([string]$Status,[string]$Result,[string]$BackupPath=$null) {
    $o=Read-UpdateStatus
    $o | Add-Member -Force -NotePropertyName status -NotePropertyValue $Status
    $o | Add-Member -Force -NotePropertyName target_version -NotePropertyValue $TargetVersion
    $o | Add-Member -Force -NotePropertyName from_version -NotePropertyValue $CurrentVersion
    $o | Add-Member -Force -NotePropertyName result -NotePropertyValue $Result
    if($BackupPath){ $o | Add-Member -Force -NotePropertyName backup_path -NotePropertyValue $BackupPath }
    $o | Add-Member -Force -NotePropertyName updated_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o'))
    $dir=Split-Path -Parent $StatusPath
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $tmp="$StatusPath.tmp.$PID"
    $o | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $StatusPath -Force
}
function Start-InteractiveTray {
    if(!(Test-Path -LiteralPath $trayExe)){ return $false }
    if(Get-Process -Name 'AppControlManager.Tray' -ErrorAction SilentlyContinue){ return $true }

    $users=@()
    try {
        $users=@(Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserName) } |
            Select-Object -ExpandProperty UserName -Unique)
    } catch {}
    if($users.Count -eq 0){
        try {
            $consoleUser=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
            if(-not [string]::IsNullOrWhiteSpace($consoleUser)){ $users=@($consoleUser) }
        } catch {}
    }
    if($users.Count -eq 0){ return $false }

    foreach($user in $users){
        $safe=($user -replace '[^A-Za-z0-9_.-]','_')
        $taskName="AppControlManager Tray Relaunch $safe"
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            $action=New-ScheduledTaskAction -Execute $trayExe
            $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
            $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName
            $deadline=(Get-Date).AddSeconds(10)
            do {
                Start-Sleep -Milliseconds 500
                if(Get-Process -Name 'AppControlManager.Tray' -ErrorAction SilentlyContinue){ return $true }
            } while((Get-Date) -lt $deadline)
        } catch {}
        finally {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    return $false
}
function Wait-ServiceStable([string]$Name,[int]$Seconds=30) {
    $deadline=(Get-Date).AddSeconds($Seconds)
    do {
        $svc=Get-Service -Name $Name -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -eq 'Running') {
            Start-Sleep -Seconds 8
            $again=Get-Service -Name $Name -ErrorAction SilentlyContinue
            return ($again -and $again.Status -eq 'Running')
        }
        Start-Sleep -Seconds 1
    } while((Get-Date) -lt $deadline)
    return $false
}
function Get-ServiceDiagnostic([string]$Name) {
    try {
        $escaped=$Name.Replace("'","''")
        $svc=Get-CimInstance Win32_Service -Filter "Name='$escaped'" -ErrorAction Stop
        if(-not $svc){ return "service=$Name state=not-found" }
        return "service=$Name state=$($svc.State) exit_code=$($svc.ExitCode) service_exit_code=$($svc.ServiceSpecificExitCode)"
    } catch {
        return "service=$Name diagnostic_error=$($_.Exception.Message)"
    }
}
function Test-UsesRuleWorker([string]$Version) {
    $numeric=($Version.Trim() -replace '^v','' -replace '-.*$','')
    $parsed=$null
    if(-not [version]::TryParse($numeric,[ref]$parsed)){ return $true }
    return $parsed -ge ([version]'0.16.5')
}
function Start-InstalledServicesBestEffort {
    $messages=@()
    foreach($name in @($serviceName,$ruleWorkerServiceName)) {
        try {
            $service=Get-Service -Name $name -ErrorAction Stop
            Set-Service -Name $name -StartupType Automatic -ErrorAction Stop
            if($service.Status -ne 'Running'){ Start-Service -Name $name -ErrorAction Stop }
            $messages += "service=$name recovery=started"
        } catch {
            $messages += "service=$name recovery=failed error=$($_.Exception.Message)"
        }
    }
    return ($messages -join '; ')
}
function Prepare-RollbackBackup {
    $stagedService=Join-Path $StagingPath 'Service\AppControlManager.Service.exe'
    $stagedTray=Join-Path $StagingPath 'Tray\AppControlManager.Tray.exe'
    if(!(Test-Path -LiteralPath $stagedService -PathType Leaf) -or !(Test-Path -LiteralPath $stagedTray -PathType Leaf)) {
        throw 'The staged update is missing its service or tray executable.'
    }
    $currentService=Join-Path $programFiles 'AppControlManager.Service.exe'
    $currentTray=Join-Path $programFiles 'AppControlManager.Tray.exe'
    if(!(Test-Path -LiteralPath $currentService -PathType Leaf) -or !(Test-Path -LiteralPath $currentTray -PathType Leaf)) {
        throw 'The current installation is incomplete and cannot be backed up safely.'
    }
    New-Item -ItemType Directory -Path $BackupRoot,$backup -Force | Out-Null
    $saved=Join-Path $backup 'AppControlManager'
    Copy-Item -LiteralPath $programFiles -Destination $saved -Recurse -Force
    if(!(Test-Path -LiteralPath (Join-Path $saved 'AppControlManager.Service.exe') -PathType Leaf) -or
       !(Test-Path -LiteralPath (Join-Path $saved 'AppControlManager.Tray.exe') -PathType Leaf)) {
        throw 'The rollback backup is incomplete.'
    }
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$backup=Join-Path $BackupRoot ("$CurrentVersion-$stamp")
try {
    Prepare-RollbackBackup
} catch {
    Write-UpdateStatus 'failed' "Update to $TargetVersion backup preparation failed before services were stopped: $($_.Exception.Message)" $backup
    exit 1
}

Write-UpdateStatus 'installing' "Stopping AppControl Manager $CurrentVersion and installing $TargetVersion..." $backup
try {
    # Closing the tray avoids an executable file lock. The Run registry entry remains in place,
    # and we also make a best-effort interactive relaunch after the update.
    Stop-Process -Name 'AppControlManager.Tray' -Force -ErrorAction SilentlyContinue
    Stop-Service -Name $ruleWorkerServiceName -Force -ErrorAction SilentlyContinue
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    New-Item -ItemType Directory -Path $programFiles,(Join-Path $programFiles 'Scripts'),$programData -Force | Out-Null
    foreach($obsoleteValidator in @(
        'Test-AppControlManagerEndpoint-RC13-v1.ps1',
        'Test-AppControlManagerRecovery-RC13-v1.ps1'
    )) {
        Remove-Item -LiteralPath (Join-Path (Join-Path $programFiles 'Scripts') $obsoleteValidator) -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $programData $obsoleteValidator) -Force -ErrorAction SilentlyContinue
    }
    Copy-Item -LiteralPath (Join-Path $StagingPath 'Service\AppControlManager.Service.exe') -Destination (Join-Path $programFiles 'AppControlManager.Service.exe') -Force
    Copy-Item -LiteralPath (Join-Path $StagingPath 'Tray\AppControlManager.Tray.exe') -Destination $trayExe -Force
    Copy-Item -Path (Join-Path $StagingPath 'scripts\*.ps1') -Destination (Join-Path $programFiles 'Scripts') -Force
    Copy-Item -Path (Join-Path $StagingPath 'scripts\*.ps1') -Destination $programData -Force

    try { Start-Service -Name $serviceName -ErrorAction Stop }
    catch { throw "Replacement AppControl Manager service could not start: $(Get-ServiceDiagnostic $serviceName) / $($_.Exception.Message)" }
    if(-not (Wait-ServiceStable $serviceName 35)){ throw "Replacement AppControl Manager service did not remain running: $(Get-ServiceDiagnostic $serviceName)" }
    if(-not (Wait-ServiceStable $ruleWorkerServiceName 20)){ throw "Replacement AppControl Manager Rule Worker did not remain running: $(Get-ServiceDiagnostic $ruleWorkerServiceName)" }

    $trayStarted=Start-InteractiveTray
    if($trayStarted){
        Write-UpdateStatus 'installed' "AppControl Manager agent $TargetVersion installed successfully; interactive tray restarted."
    } else {
        Write-UpdateStatus 'installed' "AppControl Manager agent $TargetVersion installed successfully; tray restart deferred to service recovery or next user logon."
    }
    exit 0
}
catch {
    $failure=$_.Exception.Message
    try {
        Stop-Service -Name $ruleWorkerServiceName -Force -ErrorAction SilentlyContinue
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $saved=Join-Path $backup 'AppControlManager'
        if(!(Test-Path -LiteralPath $saved -PathType Container)){ throw 'The validated rollback backup is no longer available.' }
        Remove-Item -LiteralPath $programFiles -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $saved -Destination $programFiles -Recurse -Force
        if(Test-UsesRuleWorker $CurrentVersion) {
            try { Start-Service -Name $serviceName -ErrorAction Stop }
            catch { throw "Rollback AppControl Manager service could not start: $(Get-ServiceDiagnostic $serviceName) / $($_.Exception.Message)" }
            $rollbackOk=(Wait-ServiceStable $serviceName 25) -and (Wait-ServiceStable $ruleWorkerServiceName 20)
        } else {
            & sc.exe delete $ruleWorkerServiceName | Out-Null
            try { Start-Service -Name $serviceName -ErrorAction Stop }
            catch { throw "Legacy rollback AppControl Manager service could not start: $(Get-ServiceDiagnostic $serviceName) / $($_.Exception.Message)" }
            $rollbackOk=Wait-ServiceStable $serviceName 25
        }
        if($rollbackOk) {
            $null=Start-InteractiveTray
            Write-UpdateStatus 'rolled_back' "Update to $TargetVersion failed and AppControl Manager $CurrentVersion was restored: $failure" $backup
            exit 2
        }
        $rollbackServices="$(Get-ServiceDiagnostic $serviceName); $(Get-ServiceDiagnostic $ruleWorkerServiceName)"
        $recovery=Start-InstalledServicesBestEffort
        Write-UpdateStatus 'failed' "Update to $TargetVersion failed and rollback service startup also failed: $failure / $rollbackServices / final recovery: $recovery" $backup
    } catch {
        $rollbackFailure=$_.Exception.Message
        $recovery=Start-InstalledServicesBestEffort
        Write-UpdateStatus 'failed' "Update to $TargetVersion failed and rollback failed: $failure / $rollbackFailure / final recovery: $recovery" $backup
    }
    exit 1
}
