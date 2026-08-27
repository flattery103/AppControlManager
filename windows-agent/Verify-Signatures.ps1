param(
    [Parameter(Mandatory=$true)]
    [string[]]$Files
)
$ErrorActionPreference='Stop'

if(!$Files -or $Files.Count -eq 0){
    throw 'At least one file must be supplied for Authenticode verification.'
}

foreach($file in $Files){
    if(!(Test-Path -LiteralPath $file)){
        throw "Signature verification target does not exist: $file"
    }
    $signature=Get-AuthenticodeSignature -LiteralPath $file
    if($signature.Status -ne 'Valid'){
        throw "Authenticode signature verification failed for $file. Status: $($signature.Status)."
    }
    if(!$signature.SignerCertificate){
        throw "Authenticode signature for $file did not expose a signer certificate."
    }
    Write-Host "Signature valid: $file" -ForegroundColor Green
    Write-Host "  Signer: $($signature.SignerCertificate.Subject)" -ForegroundColor Green
}
