param(
    [string]$Configuration='Release',
    [string]$Version='0.13.1'
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$publish=Join-Path $root 'publish'
$version=$Version

if(!(Get-Command dotnet -ErrorAction SilentlyContinue)){
    throw ".NET 10 SDK is required to build AppControl Manager $version."
}

function Invoke-DotNet {
    param([Parameter(Mandatory=$true)][string[]]$Arguments,[Parameter(Mandatory=$true)][string]$Step)
    Write-Host $Step -ForegroundColor Cyan
    & dotnet @Arguments
    if($LASTEXITCODE -ne 0){ throw "$Step failed. dotnet exited with code $LASTEXITCODE." }
}

Remove-Item $publish -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $publish -Force | Out-Null

Invoke-DotNet -Step 'Restoring solution...' -Arguments @('restore',(Join-Path $root 'AppGuard.sln'))
Invoke-DotNet -Step 'Publishing AppControl Manager Windows service...' -Arguments @(
    'publish',(Join-Path $root 'src\AppGuard.Service\AppGuard.Service.csproj'),'-c',$Configuration,'-r','win-x64','--self-contained','true','--no-restore','-p:PublishSingleFile=true',"-p:Version=$version",'-o',(Join-Path $publish 'Service')
)
Invoke-DotNet -Step 'Publishing AppControl Manager tray application...' -Arguments @(
    'publish',(Join-Path $root 'src\AppGuard.Tray\AppGuard.Tray.csproj'),'-c',$Configuration,'-r','win-x64','--self-contained','true','--no-restore','-p:PublishSingleFile=true',"-p:Version=$version",'-o',(Join-Path $publish 'Tray')
)

$serviceExe=Join-Path $publish 'Service\AppControlManager.Service.exe'
$trayExe=Join-Path $publish 'Tray\AppControlManager.Tray.exe'
if(!(Test-Path $serviceExe)){ throw "Service publish completed without producing $serviceExe" }
if(!(Test-Path $trayExe)){ throw "Tray publish completed without producing $trayExe" }

# Build the server-managed update package. The server validates this manifest before a release
# can be deployed, and the endpoint verifies the package SHA256 before activation.
Write-Host 'Building managed agent update package...' -ForegroundColor Cyan
$packageRoot=Join-Path $publish 'PackageRoot'
$packageDir=Join-Path $publish 'Packages'
New-Item -ItemType Directory -Path "$packageRoot\Service","$packageRoot\Tray","$packageRoot\scripts",$packageDir -Force | Out-Null
Copy-Item $serviceExe "$packageRoot\Service\AppControlManager.Service.exe" -Force
Copy-Item $trayExe "$packageRoot\Tray\AppControlManager.Tray.exe" -Force
Copy-Item "$root\scripts\*.ps1" "$packageRoot\scripts\" -Force
$manifestFiles=@()
Get-ChildItem $packageRoot -Recurse -File | ForEach-Object {
    $rel=$_.FullName.Substring($packageRoot.Length+1).Replace('\','/')
    $manifestFiles += [ordered]@{ path=$rel; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash; size=$_.Length }
}
$manifest=[ordered]@{ product='AppControl Manager Agent'; version=$version; platform='win-x64'; created_at=(Get-Date).ToUniversalTime().ToString('o'); files=$manifestFiles }
$manifest | ConvertTo-Json -Depth 8 | Set-Content "$packageRoot\agent-manifest.json" -Encoding UTF8
$package=Join-Path $packageDir "AppControlManager-Agent-$version-win-x64.zip"
Compress-Archive -Path "$packageRoot\*" -DestinationPath $package -CompressionLevel Optimal -Force
$packageHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $package).Hash
Set-Content -LiteralPath "$package.sha256" -Value "$packageHash  $(Split-Path $package -Leaf)" -Encoding ascii
Write-Host "  Package: $package" -ForegroundColor Green
Write-Host "  SHA256:  $packageHash" -ForegroundColor Green

# Build a single-file first-install executable with the exact same payload embedded inside it.
Write-Host 'Building single-file Windows installer...' -ForegroundColor Cyan
$installerPayload=Join-Path $root 'src\AppControlManager.Installer\Payload\agent-payload.zip'
New-Item -ItemType Directory -Path (Split-Path $installerPayload -Parent) -Force | Out-Null
Copy-Item $package $installerPayload -Force
Invoke-DotNet -Step 'Publishing AppControl Manager single-file installer...' -Arguments @(
    'publish',(Join-Path $root 'src\AppControlManager.Installer\AppControlManager.Installer.csproj'),'-c',$Configuration,'-r','win-x64','--self-contained','true','-p:PublishSingleFile=true',"-p:Version=$version",'-o',(Join-Path $publish 'Installer')
)
$rawInstaller=Join-Path $publish 'Installer\AppControlManager-Installer.exe'
$installer=Join-Path $publish "Installer\AppControlManager-Installer-$version.exe"
if(!(Test-Path $rawInstaller)){ throw "Installer publish completed without producing $rawInstaller" }
Move-Item $rawInstaller $installer -Force
$installerHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash
Set-Content -LiteralPath "$installer.sha256" -Value "$installerHash  $(Split-Path $installer -Leaf)" -Encoding ascii

Write-Host "Published AppControl Manager $version artifacts to $publish" -ForegroundColor Green
Write-Host "  Service:   $serviceExe" -ForegroundColor Green
Write-Host "  Tray:      $trayExe" -ForegroundColor Green
Write-Host "  Update ZIP:$package" -ForegroundColor Green
Write-Host "  Installer: $installer" -ForegroundColor Green

# The embedded package is a build artifact; do not leave it in the source tree.
Remove-Item -LiteralPath $installerPayload -Force -ErrorAction SilentlyContinue
