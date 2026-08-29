$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$publisher = Get-Content -LiteralPath (Join-Path $root '.github/scripts/Publish-GitHubRelease.ps1') -Raw
$workflow = Get-Content -LiteralPath (Join-Path $root '.github/workflows/release.yml') -Raw

if ($publisher -notmatch "-rc\\\.\\d\+\$") { throw 'Publisher does not recognize RC versions.' }
if ($publisher -notmatch "--prerelease") { throw 'Publisher does not mark RC releases as prereleases.' }
if ($publisher -notmatch "--latest=false") { throw 'Publisher does not prevent RC releases from becoming latest stable.' }
if ($workflow -notmatch 'Test-Prerelease-Publishing\.ps1') { throw 'Release workflow does not run prerelease publication tests.' }

$global:LASTEXITCODE = 0
Write-Host 'Prerelease publication behavior tests passed.'
