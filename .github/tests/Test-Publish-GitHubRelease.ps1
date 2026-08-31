$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$publisher = Join-Path $repositoryRoot '.github/scripts/Publish-GitHubRelease.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("AppControlManager-ReleaseProbe-" + [Guid]::NewGuid().ToString('N'))
$assets = Join-Path $testRoot 'release'
$calls = Join-Path $testRoot 'calls.txt'
$fakeGh = Join-Path $testRoot 'gh.cmd'
$notes = Join-Path $testRoot 'release-notes.txt'

try {
    New-Item -ItemType Directory -Path $assets -Force | Out-Null
    1..6 | ForEach-Object {
        Set-Content -LiteralPath (Join-Path $assets ("asset{0}.txt" -f $_)) -Value "asset $_" -Encoding ascii
    }
    Set-Content -LiteralPath $notes -Value 'Test release notes.' -Encoding ascii

    @'
@echo off
setlocal
echo %*>>"%CALLS%"
if /i "%1 %2"=="release view" (
  echo release not found 1>&2
  exit /b %PROBE_EXIT%
)
exit /b 0
'@ | Set-Content -LiteralPath $fakeGh -Encoding ascii

    $env:CALLS = $calls
    $env:PROBE_EXIT = '1'
    & $publisher -Tag 'v0.18.0' -Version '0.18.0' -AssetsDirectory $assets -NotesFile $notes -GhCommand $fakeGh
    if (-not (Select-String -LiteralPath $calls -SimpleMatch 'release create v0.18.0')) {
        throw 'Missing release was not created.'
    }

    Remove-Item -LiteralPath $calls -Force
    $env:PROBE_EXIT = '1'
    & $publisher -Tag 'v1.0.0-rc.1' -Version '1.0.0-rc.1' -AssetsDirectory $assets -NotesFile $notes -GhCommand $fakeGh
    $rcCreate = Get-Content -LiteralPath $calls | Where-Object { $_ -like 'release create*' } | Select-Object -Last 1
    if ($rcCreate -notlike 'release create v1.0.0-rc.1*') {
        throw 'Missing RC release creation invocation.'
    }
    if ($rcCreate -notmatch '(?:^|\s)--latest(?:\s|$)') {
        throw "RC release creation did not publish as latest: $rcCreate"
    }
    if ($rcCreate -match '(?:^|\s)--prerelease(?:\s|$)') {
        throw "RC release creation unexpectedly marked the release as prerelease: $rcCreate"
    }

    Remove-Item -LiteralPath $calls -Force
    $env:PROBE_EXIT = '2'
    $threw = $false
    try {
        & $publisher -Tag 'v0.18.0' -Version '0.18.0' -AssetsDirectory $assets -NotesFile $notes -GhCommand $fakeGh
    }
    catch {
        $threw = $true
        if ($_.Exception.Message -notmatch 'GitHub release probe failed') {
            throw
        }
    }
    if (-not $threw) {
        throw 'Unexpected GitHub release probe failure did not throw.'
    }
    if (Select-String -LiteralPath $calls -SimpleMatch 'release create' -ErrorAction SilentlyContinue) {
        throw 'Unexpected GitHub release probe failure created a release.'
    }
}
finally {
    Remove-Item Env:CALLS -ErrorAction SilentlyContinue
    Remove-Item Env:PROBE_EXIT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# The second case intentionally leaves the native command exit code nonzero even
# though the expected PowerShell exception was caught and verified. GitHub's
# PowerShell wrapper exits with that stale value unless the successful test clears it.
$global:LASTEXITCODE = 0
Write-Host 'GitHub Release publication probe tests passed (2 cases).'
