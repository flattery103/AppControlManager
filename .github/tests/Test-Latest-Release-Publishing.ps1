$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$publisher = Get-Content -LiteralPath (Join-Path $root '.github/scripts/Publish-GitHubRelease.ps1') -Raw
$workflow = Get-Content -LiteralPath (Join-Path $root '.github/workflows/release.yml') -Raw

if ($publisher -notmatch '--latest') { throw 'Publisher does not publish releases as latest.' }
if ($publisher -match '--latest=false') { throw 'Publisher still prevents RC releases from becoming latest.' }
if ($publisher -match '--prerelease(?!\=false)') { throw 'Publisher still creates RC releases as prereleases.' }
if ($workflow -notmatch 'Test-Latest-Release-Publishing\.ps1') { throw 'Release workflow does not run latest-release publication tests.' }

$global:LASTEXITCODE = 0
Write-Host 'Latest-release publication behavior tests passed.'
