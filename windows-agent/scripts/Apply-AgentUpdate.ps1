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
function Ensure-RuleWorker {
    $root=Join-Path $programData 'RuleWorker'
    $jobs=Join-Path $root 'Jobs'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    & icacls.exe $root '/inheritance:r' | Out-Null
    if($LASTEXITCODE -ne 0){ throw "Could not disable RuleWorker ACL inheritance." }
    foreach($grant in @('*S-1-5-18:(OI)(CI)(F)','*S-1-5-32-544:(OI)(CI)(F)','*S-1-5-19:(OI)(CI)(M)')) {
        & icacls.exe $root '/grant:r' $grant | Out-Null
        if($LASTEXITCODE -ne 0){ throw "Could not secure AppControl Manager RuleWorker directory." }
    }
    New-Item -ItemType Directory -Path $jobs -Force | Out-Null
    $workerBin='"C:\Program Files\AppControlManager\AppControlManager.Service.exe" --rule-worker'
    if(Get-Service -Name $ruleWorkerServiceName -ErrorAction SilentlyContinue) {
        & sc.exe config $ruleWorkerServiceName binPath= $workerBin start= auto obj= 'NT AUTHORITY\LocalService' DisplayName= 'AppControl Manager Rule Worker' | Out-Null
    } else {
        & sc.exe create $ruleWorkerServiceName binPath= $workerBin start= auto obj= 'NT AUTHORITY\LocalService' DisplayName= 'AppControl Manager Rule Worker' | Out-Null
    }
    if($LASTEXITCODE -ne 0){ throw "Could not create/configure AppControl Manager Rule Worker service." }
    & sc.exe description $ruleWorkerServiceName 'AppControl Manager generation-only ConfigCI worker running as Local Service' | Out-Null
}
function Wait-ServiceStable([int]$Seconds=30) {
    $deadline=(Get-Date).AddSeconds($Seconds)
    do {
        $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if($svc -and $svc.Status -eq 'Running') {
            Start-Sleep -Seconds 8
            $again=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            return ($again -and $again.Status -eq 'Running')
        }
        Start-Sleep -Seconds 1
    } while((Get-Date) -lt $deadline)
    return $false
}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$backup=Join-Path $BackupRoot ("$CurrentVersion-$stamp")
New-Item -ItemType Directory -Path $BackupRoot,$backup -Force | Out-Null
Write-UpdateStatus 'installing' "Stopping AppControl Manager $CurrentVersion and installing $TargetVersion..." $backup

try {
    # Preserve a rollback copy before replacing any binaries.
    if(Test-Path -LiteralPath $programFiles){ Copy-Item -LiteralPath $programFiles -Destination (Join-Path $backup 'AppControlManager') -Recurse -Force }

    # Closing the tray avoids an executable file lock. The Run registry entry remains in place,
    # and we also make a best-effort interactive relaunch after the update.
    Stop-Process -Name 'AppControlManager.Tray' -Force -ErrorAction SilentlyContinue
    Stop-Service -Name $ruleWorkerServiceName -Force -ErrorAction SilentlyContinue
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    New-Item -ItemType Directory -Path $programFiles,(Join-Path $programFiles 'Scripts'),$programData -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $StagingPath 'Service\AppControlManager.Service.exe') -Destination (Join-Path $programFiles 'AppControlManager.Service.exe') -Force
    Copy-Item -LiteralPath (Join-Path $StagingPath 'Tray\AppControlManager.Tray.exe') -Destination $trayExe -Force
    Copy-Item -Path (Join-Path $StagingPath 'scripts\*.ps1') -Destination (Join-Path $programFiles 'Scripts') -Force
    Copy-Item -Path (Join-Path $StagingPath 'scripts\*.ps1') -Destination $programData -Force

    Ensure-RuleWorker
    Start-Service -Name $ruleWorkerServiceName
    Start-Service -Name $serviceName
    if(-not (Wait-ServiceStable 35)){ throw "Replacement AppControl Manager service did not remain running." }

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
        if(Test-Path -LiteralPath $saved) {
            Remove-Item -LiteralPath $programFiles -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item -LiteralPath $saved -Destination $programFiles -Recurse -Force
        }
        if(([version]$CurrentVersion) -ge ([version]'0.16.5')) {
            Ensure-RuleWorker
            Start-Service -Name $ruleWorkerServiceName -ErrorAction Stop
        } else {
            & sc.exe delete $ruleWorkerServiceName | Out-Null
        }
        Start-Service -Name $serviceName -ErrorAction Stop
        $rollbackOk=Wait-ServiceStable 25
        if($rollbackOk) {
            $null=Start-InteractiveTray
            Write-UpdateStatus 'rolled_back' "Update to $TargetVersion failed and AppControl Manager $CurrentVersion was restored: $failure" $backup
            exit 2
        }
        Write-UpdateStatus 'failed' "Update to $TargetVersion failed and rollback service startup also failed: $failure" $backup
    } catch {
        Write-UpdateStatus 'failed' "Update to $TargetVersion failed and rollback failed: $failure / $($_.Exception.Message)" $backup
    }
    exit 1
}
