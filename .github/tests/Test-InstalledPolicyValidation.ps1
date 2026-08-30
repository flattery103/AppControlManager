$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\..\windows-agent\scripts\GeneratedPolicyValidation.ps1"

function Assert-Throws([string]$Name,[scriptblock]$Action) {
    try {
        & $Action
        throw "Mutation survived: $Name"
    } catch {
        if($_.Exception.Message -like 'Mutation survived:*'){ throw }
    }
}

$policyId='{11111111-1111-1111-1111-111111111111}'
$installed=[pscustomobject]@{
    PolicyID='11111111-1111-1111-1111-111111111111'
    IsEnforced=$true
    IsAuthorized=$true
}

$actual=Assert-InstalledGeneratedPolicy -Policies @($installed) -PolicyId $policyId
if($actual.PolicyID -ne $installed.PolicyID -or $actual.IsEnforced -ne $true -or $actual.IsAuthorized -ne $true){
    throw 'Exact installed policy was not returned.'
}

Assert-Throws 'empty policy list accepted' { Assert-InstalledGeneratedPolicy -Policies @() -PolicyId $policyId }
Assert-Throws 'multiple matching policies accepted' { Assert-InstalledGeneratedPolicy -Policies @($installed,$installed) -PolicyId $policyId }
Assert-Throws 'missing enforcement property accepted' {
    Assert-InstalledGeneratedPolicy -Policies @([pscustomobject]@{ PolicyID=$policyId; IsAuthorized=$true }) -PolicyId $policyId
}
Assert-Throws 'missing authorization property accepted' {
    Assert-InstalledGeneratedPolicy -Policies @([pscustomobject]@{ PolicyID=$policyId; IsEnforced=$true }) -PolicyId $policyId
}
Assert-Throws 'string enforcement value accepted as true' {
    Assert-InstalledGeneratedPolicy -Policies @([pscustomobject]@{ PolicyID=$policyId; IsEnforced='false'; IsAuthorized=$true }) -PolicyId $policyId
}
Assert-Throws 'false authorization accepted' {
    Assert-InstalledGeneratedPolicy -Policies @([pscustomobject]@{ PolicyID=$policyId; IsEnforced=$true; IsAuthorized=$false }) -PolicyId $policyId
}

Write-Output 'Installed policy validation behavior tests passed (7 cases).'
