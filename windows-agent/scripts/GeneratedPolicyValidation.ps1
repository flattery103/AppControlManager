function Assert-InstalledGeneratedPolicy {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Policies,
        [Parameter(Mandatory=$true)][string]$PolicyId
    )
    $normalized=($PolicyId -replace '[{}]','').ToLowerInvariant()
    $matchingPolicies=@($Policies | Where-Object { (([string]$_.PolicyID) -replace '[{}]','').ToLowerInvariant() -eq $normalized })
    if($matchingPolicies.Count -ne 1){ throw "Expected exactly one installed generated policy $PolicyId; CiTool returned $($matchingPolicies.Count)." }
    $installed=$matchingPolicies[0]
    if(-not ($installed.PSObject.Properties.Name -contains 'IsEnforced')){ throw "Installed generated policy $PolicyId IsEnforced property is missing." }
    if(-not ($installed.PSObject.Properties.Name -contains 'IsAuthorized')){ throw "Installed generated policy $PolicyId IsAuthorized property is missing." }
    if($installed.IsEnforced -isnot [bool] -or $installed.IsEnforced -ne $true){ throw "Installed generated policy $PolicyId is not currently enforced." }
    if($installed.IsAuthorized -isnot [bool] -or $installed.IsAuthorized -ne $true){ throw "Installed generated policy $PolicyId is not authorized." }
    return $installed
}
