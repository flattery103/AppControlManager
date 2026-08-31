param(
    [string]$Configuration='Release',
    [string]$Version='1.0.0-rc.13',
    [ValidateSet('Full','Prepare','Package')]
    [string]$Stage='Full',
    [switch]$RequireSignedPayload
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$publish=Join-Path $root 'publish'
$version=$Version
$numericVersion=($version -replace '-.*$','') + '.0'
$serviceExe=Join-Path $publish 'Service\AppControlManager.Service.exe'
$trayExe=Join-Path $publish 'Tray\AppControlManager.Tray.exe'

if(!(Get-Command dotnet -ErrorAction SilentlyContinue)){
    throw ".NET 10 SDK is required to build AppControl Manager $version."
}

function Invoke-DotNet {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Step
    )
    Write-Host $Step -ForegroundColor Cyan
    & dotnet @Arguments
    if($LASTEXITCODE -ne 0){ throw "$Step failed. dotnet exited with code $LASTEXITCODE." }
}

function Assert-ValidAuthenticodeSignature {
    param([Parameter(Mandatory=$true)][string]$Path)
    if(!(Test-Path -LiteralPath $Path)){ throw "Signed payload file does not exist: $Path" }
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if($signature.Status -ne 'Valid'){
        throw "Authenticode signature validation failed for $Path. Status: $($signature.Status)."
    }
    $subject=$signature.SignerCertificate.Subject
    Write-Host "  Signature valid: $(Split-Path $Path -Leaf) [$subject]" -ForegroundColor Green
}

if($Stage -eq 'Full' -or $Stage -eq 'Prepare'){
    Remove-Item $publish -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $publish -Force | Out-Null

    Invoke-DotNet -Step 'Restoring solution...' -Arguments @('restore',(Join-Path $root 'AppGuard.sln'))
    Invoke-DotNet -Step 'Publishing AppControl Manager Windows service...' -Arguments @(
        'publish',(Join-Path $root 'src\AppGuard.Service\AppGuard.Service.csproj'),'-c',$Configuration,'-r','win-x64','--self-contained','true','--no-restore','-p:PublishSingleFile=true',"-p:Version=$version","-p:FileVersion=$numericVersion","-p:AssemblyVersion=$numericVersion","-p:InformationalVersion=$version",'-o',(Join-Path $publish 'Service')
    )
    Invoke-DotNet -Step 'Publishing AppControl Manager tray application...' -Arguments @(
        'publish',(Join-Path $root 'src\AppGuard.Tray\AppGuard.Tray.csproj'),'-c',$Configuration,'-r','win-x64','--self-contained','true','--no-restore','-p:PublishSingleFile=true',"-p:Version=$version","-p:FileVersion=$numericVersion","-p:AssemblyVersion=$numericVersion","-p:InformationalVersion=$version",'-o',(Join-Path $publish 'Tray')
    )

    if(!(Test-Path $serviceExe)){ throw "Service publish completed without producing $serviceExe" }
    if(!(Test-Path $trayExe)){ throw "Tray publish completed without producing $trayExe" }

    Write-Host "Prepared AppControl Manager $version Windows binaries." -ForegroundColor Green
    Write-Host "  Service: $serviceExe" -ForegroundColor Green
    Write-Host "  Tray:    $trayExe" -ForegroundColor Green

    if($Stage -eq 'Prepare'){
        return
    }
}

if($Stage -eq 'Package'){
    New-Item -ItemType Directory -Path $publish -Force | Out-Null
}

if(!(Test-Path $serviceExe)){ throw "Packaging requires the prepared service binary: $serviceExe" }
if(!(Test-Path $trayExe)){ throw "Packaging requires the prepared tray binary: $trayExe" }

if($RequireSignedPayload){
    Write-Host 'Verifying signed service and tray payload before packaging...' -ForegroundColor Cyan
    Assert-ValidAuthenticodeSignature -Path $serviceExe
    Assert-ValidAuthenticodeSignature -Path $trayExe
}

# Build the server-managed update package from the already prepared payload. In the
# GitHub Release workflow these executables have been signed before this stage.
Write-Host 'Building managed agent update package...' -ForegroundColor Cyan
$packageRoot=Join-Path $publish 'PackageRoot'
$packageDir=Join-Path $publish 'Packages'
$installerDir=Join-Path $publish 'Installer'
Remove-Item $packageRoot,$packageDir,$installerDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$packageRoot\Service","$packageRoot\Tray","$packageRoot\scripts",$packageDir -Force | Out-Null
Copy-Item $serviceExe "$packageRoot\Service\AppControlManager.Service.exe" -Force
Copy-Item $trayExe "$packageRoot\Tray\AppControlManager.Tray.exe" -Force
Copy-Item "$root\scripts\*.ps1" "$packageRoot\scripts\" -Force
$manifestFiles=@()
Get-ChildItem $packageRoot -Recurse -File | ForEach-Object {
    $rel=$_.FullName.Substring($packageRoot.Length+1).Replace('\','/')
    $manifestFiles += [ordered]@{ path=$rel; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash; size=$_.Length }
}
$manifest=[ordered]@{
    product='AppControl Manager Agent'
    version=$version
    platform='win-x64'
    created_at=(Get-Date).ToUniversalTime().ToString('o')
    files=$manifestFiles
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content "$packageRoot\agent-manifest.json" -Encoding UTF8
$package=Join-Path $packageDir "AppControlManager-Agent-$version-win-x64.zip"
Compress-Archive -Path "$packageRoot\*" -DestinationPath $package -CompressionLevel Optimal -Force
$packageHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $package).Hash
Set-Content -LiteralPath "$package.sha256" -Value "$packageHash  $(Split-Path $package -Leaf)" -Encoding ascii
Write-Host "  Package: $package" -ForegroundColor Green
Write-Host "  SHA256:  $packageHash" -ForegroundColor Green

# Build a single-file first-install/in-place-repair executable with the signed agent package embedded inside it.
Write-Host 'Building single-file Windows installer and repair package...' -ForegroundColor Cyan
$installerPayload=Join-Path $root 'src\AppControlManager.Installer\Payload\agent-payload.zip'
New-Item -ItemType Directory -Path (Split-Path $installerPayload -Parent) -Force | Out-Null
Copy-Item $package $installerPayload -Force
try {
    Invoke-DotNet -Step 'Publishing AppControl Manager single-file installer...' -Arguments @(
        'publish',(Join-Path $root 'src\AppControlManager.Installer\AppControlManager.Installer.csproj'),'-c',$Configuration,'-r','win-x64','--self-contained','true','-p:PublishSingleFile=true',"-p:Version=$version",'-o',$installerDir
    )
}
finally {
    # The embedded package is a build artifact; do not leave it in the source tree.
    Remove-Item -LiteralPath $installerPayload -Force -ErrorAction SilentlyContinue
}
$rawInstaller=Join-Path $installerDir 'AppControlManager-Installer.exe'
$installer=Join-Path $installerDir "AppControlManager-Installer-$version.exe"
if(!(Test-Path $rawInstaller)){ throw "Installer publish completed without producing $rawInstaller" }
Move-Item $rawInstaller $installer -Force
$installerHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash
Set-Content -LiteralPath "$installer.sha256" -Value "$installerHash  $(Split-Path $installer -Leaf)" -Encoding ascii

Write-Host "Published AppControl Manager $version artifacts to $publish" -ForegroundColor Green
Write-Host "  Service:    $serviceExe" -ForegroundColor Green
Write-Host "  Tray:       $trayExe" -ForegroundColor Green
Write-Host "  Update ZIP: $package" -ForegroundColor Green
Write-Host "  Installer:  $installer" -ForegroundColor Green
if($RequireSignedPayload){
    Write-Host 'The agent package contains verified signed Service and Tray executables.' -ForegroundColor Green
}
