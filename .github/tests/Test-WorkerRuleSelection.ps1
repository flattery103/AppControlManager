$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\..\windows-agent\scripts\Common.ps1"

function Assert-Equal($Expected,$Actual,[string]$Name) {
    if($Expected -ne $Actual){ throw "$Name expected $Expected but received $Actual" }
}

$complete=[pscustomobject]@{
    publisher='CN=Google LLC'
    product_name='Google Chrome'
    file_version='152.0.7977.64'
}
$metadataFree=[pscustomobject]@{
    publisher='CN=Google LLC'
    product_name=$null
    file_version=$null
}
$unsigned=[pscustomobject]@{
    publisher=$null
    product_name='Example Application'
    file_version='1.0.0.0'
}

Assert-Equal $true (Test-AppGuardFilePublisherCandidate $complete) 'complete signed metadata'
Assert-Equal $false (Test-AppGuardFilePublisherCandidate $metadataFree) 'publisher-only metadata'
Assert-Equal $false (Test-AppGuardFilePublisherCandidate $unsigned) 'unsigned metadata'

Write-Output 'Worker rule-selection behavior tests passed (3 cases).'
