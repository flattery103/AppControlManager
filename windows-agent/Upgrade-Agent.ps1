$ErrorActionPreference='Stop'
$programData='C:\ProgramData\AppControlManager'
$programFiles='C:\Program Files\AppControlManager'
$legacyProgramData='C:\ProgramData\AppGuardPOC'
$legacyProgramFiles='C:\Program Files\AppGuardPOC'
$publish=Join-Path $PSScriptRoot 'publish'
$serviceExe=Join-Path $publish 'Service\AppControlManager.Service.exe'
$trayExe=Join-Path $publish 'Tray\AppControlManager.Tray.exe'
$ruleWorkerServiceName='AppControlManagerRuleWorker'

if(!(Test-Path $serviceExe)){ throw 'Published binaries not found. Run .\Build.ps1 first or use the GitHub Actions artifact.' }
if(!(Test-Path $trayExe)){ throw 'Published tray binary not found. Run .\Build.ps1 first or use the GitHub Actions artifact.' }
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ throw 'Run this upgrade as Administrator.' }

$currentConfig=Join-Path $programData 'config.json'
$legacyConfig=Join-Path $legacyProgramData 'config.json'
if(!(Test-Path $currentConfig) -and !(Test-Path $legacyConfig)){ throw 'Existing AppControl Manager/AppGuard enrollment not found.' }

# Pre-authorize the new signed/unsigned POC binaries before stopping the currently trusted agent.
# On the first rebrand upgrade the trusted helper still lives in the legacy ProgramData directory.
$trustRoot = if(Test-Path $currentConfig){ $programData } else { $legacyProgramData }
$trustHelper=Join-Path $trustRoot 'New-SupplementalForFiles.ps1'
$basePolicy=Join-Path $trustRoot 'Policies\BasePolicy.xml'
$binaryList=@($serviceExe,$trayExe)
$preauthPolicyId=$null
Write-Host 'Preparing AppControl Manager 1.0.0-rc.9 binaries for the current enforcement policy...'
if((Test-Path $trustHelper) -and (Test-Path $basePolicy)) {
    try {
        $trustResult=& $trustHelper -FilePath $binaryList -Name 'AppControl Manager 1.0.0-rc.9 Core Binaries' -AsObject -AlreadyExpanded
        $preauthPolicyId=[string]$trustResult.policy_id
        Write-Host "Created supplemental allow policy for the new service/tray binaries: $preauthPolicyId" -ForegroundColor Green
    } catch {
        throw "Could not pre-authorize the 1.0.0-rc.9 binaries: $($_.Exception.Message)"
    }
}

Write-Host 'Stopping current agent/tray...'
try { Stop-Process -Name 'AppControlManager.Tray' -Force -ErrorAction SilentlyContinue } catch {}
try { Stop-Process -Name 'AppGuard.Tray' -Force -ErrorAction SilentlyContinue } catch {}
try { Stop-Service $ruleWorkerServiceName -Force -ErrorAction SilentlyContinue } catch {}
try { Stop-Service AppControlManager -Force -ErrorAction SilentlyContinue } catch {}
try { Stop-Service AppGuardPOC -Force -ErrorAction SilentlyContinue } catch {}
try { Stop-ScheduledTask -TaskName 'AppGuard POC Agent' -ErrorAction SilentlyContinue } catch {}
try { Unregister-ScheduledTask -TaskName 'AppGuard POC Agent' -Confirm:$false -ErrorAction SilentlyContinue } catch {}

# First 0.7.x upgrade: migrate enrollment, state, policies, log and cached block metadata to the new brand path.
if(!(Test-Path $currentConfig) -and (Test-Path $legacyConfig)) {
    Write-Host 'Migrating AppGuardPOC ProgramData to C:\ProgramData\AppControlManager...'
    New-Item -ItemType Directory -Path $programData -Force | Out-Null
    Copy-Item "$legacyProgramData\*" $programData -Recurse -Force
}
New-Item -ItemType Directory -Path $programData,$programFiles,"$programFiles\Scripts","$programData\Policies","$programData\Updates","$programData\RuleWorker" -Force | Out-Null
& icacls.exe "$programData\RuleWorker" '/inheritance:r' | Out-Null
if($LASTEXITCODE -ne 0){ throw 'Could not disable RuleWorker ACL inheritance.' }
foreach($grant in @('*S-1-5-18:(OI)(CI)(F)','*S-1-5-32-544:(OI)(CI)(F)','*S-1-5-19:(OI)(CI)(M)')) {
    & icacls.exe "$programData\RuleWorker" '/grant:r' $grant | Out-Null
    if($LASTEXITCODE -ne 0){ throw 'Could not secure AppControl Manager RuleWorker directory.' }
}
New-Item -ItemType Directory -Path "$programData\RuleWorker\Jobs" -Force | Out-Null
if(-not [string]::IsNullOrWhiteSpace($preauthPolicyId)) {
    [ordered]@{ version='1.0.0-rc.9'; preauth_policy_id=$preauthPolicyId } | ConvertTo-Json | Set-Content -LiteralPath "$programData\Updates\current-update.json" -Encoding UTF8
}

Copy-Item "$PSScriptRoot\scripts\*.ps1" "$programFiles\Scripts\" -Force
Copy-Item "$PSScriptRoot\scripts\*.ps1" "$programData\" -Force
Copy-Item $serviceExe "$programFiles\AppControlManager.Service.exe" -Force
Copy-Item $trayExe "$programFiles\AppControlManager.Tray.exe" -Force

# Remove the old service registration after data has been copied. Legacy files are intentionally retained
# for rollback during this POC phase, but nothing is left configured to execute from them.
if(Get-Service AppGuardPOC -ErrorAction SilentlyContinue) {
    try { sc.exe delete AppGuardPOC | Out-Null } catch {}
    Start-Sleep 1
}
if(!(Get-Service AppControlManager -ErrorAction SilentlyContinue)) {
    New-Service -Name AppControlManager -BinaryPathName '"C:\Program Files\AppControlManager\AppControlManager.Service.exe"' -DisplayName 'AppControl Manager Agent' -Description 'AppControl Manager application-control agent' -StartupType Automatic | Out-Null
}

Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'AppGuardTray' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'AppControlManagerTray' -PropertyType String -Value '"C:\Program Files\AppControlManager\AppControlManager.Tray.exe"' -Force | Out-Null
Start-Service AppControlManager -ErrorAction Stop
$workerDeadline=(Get-Date).AddSeconds(30)
do {
    $worker=Get-Service $ruleWorkerServiceName -ErrorAction SilentlyContinue
    if($worker -and $worker.Status -eq 'Running'){ break }
    Start-Sleep -Seconds 1
} while((Get-Date) -lt $workerDeadline)
if(-not $worker -or $worker.Status -ne 'Running'){ throw 'AppControl Manager Rule Worker did not start after the main service provisioned it.' }
Start-Process "$programFiles\AppControlManager.Tray.exe" -ErrorAction SilentlyContinue
Write-Host 'AppControl Manager endpoint upgraded to 1.0.0-rc.9.' -ForegroundColor Green
Write-Host 'Enrollment, state, learned data, block cache, logs and installed Windows App Control policies were preserved.'
Write-Host 'Legacy AppGuardPOC folders were retained for rollback but are no longer used.' -ForegroundColor Yellow
