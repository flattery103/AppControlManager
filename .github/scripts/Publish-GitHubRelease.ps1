[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Tag,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$AssetsDirectory,

    [Parameter()]
    [string]$NotesFile,

    [Parameter()]
    [string]$GhCommand = 'gh'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$releaseNotes = if ([string]::IsNullOrWhiteSpace($NotesFile)) {
    Join-Path $repositoryRoot "$Version-RELEASE.txt"
}
else {
    $NotesFile
}
if (-not (Test-Path -LiteralPath $releaseNotes -PathType Leaf)) {
    throw "Release notes file was not found: $releaseNotes"
}

if (-not (Test-Path -LiteralPath $AssetsDirectory -PathType Container)) {
    throw "Release assets directory was not found: $AssetsDirectory"
}

$assets = @(Get-ChildItem -LiteralPath $AssetsDirectory -File | ForEach-Object { $_.FullName })
if ($assets.Count -ne 6) {
    throw "Expected six release assets in $AssetsDirectory, found $($assets.Count)."
}

$probeError = [System.IO.Path]::GetTempFileName()
try {
    $probeCommand = '"{0}" release view "{1}" 2> "{2}"' -f $GhCommand, $Tag, $probeError
    & cmd.exe /d /c $probeCommand
    $probeExitCode = $LASTEXITCODE

    if ($probeExitCode -eq 0) {
        & $GhCommand release upload $Tag @assets --clobber
        if ($LASTEXITCODE -ne 0) {
            throw 'GitHub release asset upload failed.'
        }

        & $GhCommand release edit $Tag --title "AppControl Manager $Version" --notes-file $releaseNotes --latest --prerelease=false
        if ($LASTEXITCODE -ne 0) {
            throw 'GitHub release update failed.'
        }
    }
    elseif ($probeExitCode -eq 1) {
        & $GhCommand release create $Tag --title "AppControl Manager $Version" --notes-file $releaseNotes --verify-tag --latest @assets
        if ($LASTEXITCODE -ne 0) {
            throw 'GitHub release creation failed.'
        }
    }
    else {
        $probeMessage = (Get-Content -LiteralPath $probeError -Raw -ErrorAction SilentlyContinue).Trim()
        throw "GitHub release probe failed with exit code $probeExitCode. $probeMessage"
    }
}
finally {
    Remove-Item -LiteralPath $probeError -Force -ErrorAction SilentlyContinue
}
