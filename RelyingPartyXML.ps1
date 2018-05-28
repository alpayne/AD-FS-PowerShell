<#
.SYNOPSIS
Export and Import AD FS SAML Relying Parties

.DESCRIPTION
Script exports all SAML Relying Party configurations on a Microsoft AD FS server to XML files and/or imports
previously exported XML files into a new AD FS server. Relying Parties must be unique, so script will not 
overwrite an existing Relying Party configuration. 


.PARAMETER FilePath
Specifies directory for exported XML files, or a list of XML files for importing (wildcards supported).

.NOTES
Version:        1.0
Author:         Al Payne
#>

[CmdletBinding(DefaultParameterSetName="Import")]
Param(
  [Parameter(Mandatory = $True, ParameterSetName = "Export")]
  [switch]$Export,

  [Parameter(Mandatory = $True, ParameterSetName = "Import")]
  [switch]$Import,
  
  [Parameter(Mandatory = $True, ValueFromRemainingArguments = $True)]
  [string[]]$FilePath
)

# build regexp of invalid filename characters to filter
$invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
$fileNameRegex = "[{0}]" -f [RegEx]::Escape($invalidChars) 

function Import-ReplyingParty {
  param(
    [object]$rp
  )
 
  # Create the Relying Party and add Identifiers 
  Add-ADFSRelyingPartyTrust -Name $rp.Name -Identifier $rp.Identifier
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -Notes "$rp.Notes"

  # Add Endpoints
  $endPoints = @()
  foreach ($SamlEndpoint in $rp.SamlEndpoints) {
    if ($SamlEndpoint.ResponseLocation) {
      $endPoints += New-ADFSSamlEndpoint -Binding $SamlEndpoint.Binding -Protocol $SamlEndpoint.Protocol `
        -Uri $SamlEndpoint.Location -Index $SamlEndpoint.Index -IsDefault $SamlEndpoint.IsDefault-ResponseUri $SamlEndpoint.ResponseLocation
    } else {
      $endPoints += New-ADFSSamlEndpoint -Binding $SamlEndpoint.Binding -Protocol $SamlEndpoint.Protocol `
        -Uri $SamlEndpoint.Location -Index $SamlEndpoint.Index -IsDefault $SamlEndpoint.IsDefault
    }
  }
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -SamlEndpoint $endPoints
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -WSFedEndpoint $rp.WSFedEndpoint

  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -IssuanceTransformRules $rp.IssuanceTransformRules
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -IssuanceAuthorizationRules $rp.IssuanceAuthorizationRules
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -DelegationAuthorizationRules $rp.DelegationAuthorizationRules
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -ImpersonationAuthorizationRules $rp.ImpersonationAuthorizationRules
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -ClaimAccepted $rp.ClaimsAccepted
  
  # Monitoring
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -MetadataUrl $rp.MetadataUrl
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -MonitoringEnabled $rp.MonitoringEnabled
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -AutoUpdateEnabled $rp.AutoUpdateEnabled

  # Encryption Settings
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -EncryptionCertificate $rp.EncryptionCertificate
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -EncryptClaims $rp.EncryptClaims
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -EncryptedNameIdRequired $rp.EncryptedNameIdRequired

  # we want the ToString values for revocation check settings
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -EncryptionCertificateRevocationCheck  $rp.EncryptionCertificateRevocationCheck.ToString()
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -SigningCertificateRevocationCheck $rp.SigningCertificateRevocationCheck.ToString()

  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -RequestSigningCertificate $rp.RequestSigningCertificate
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -SignedSamlRequestsRequired $rp.SignedSamlRequestsRequired  
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -SamlResponseSignature $rp.SamlResponseSignature

  # Secure Hash Algorithm
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -SignatureAlgorithm $rp.SignatureAlgorithm

  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -ProtocolProfile $rp.ProtocolProfile
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -NotBeforeSkew $rp.NotBeforeSkew
  Set-ADFSRelyingPartyTrust -TargetName $rp.Name -TokenLifetime $rp.TokenLifetime

  # Enable the RP if it was previously enabled
  if ($rp.Enabled) {
    Enable-AdfsRelyingPartyTrust -TargetName $rp.Name
  }
}

# Main code starts here
#
if ($Export) {
  Write-Verbose("Exporting AD FS Relying Parties")
  New-Item -ItemType Directory -Force -Path $FilePath
  $allRPs = Get-AdfsRelyingPartyTrust
  foreach ($rp in $allRPs) {
    $fileName = $($rp.Name) -replace $fileNameRegex, '-'
    $fileName = $fileName + '.xml'
    $xmlFile = Join-Path $FilePath -ChildPath $fileName
    Write-Verbose("Exporting: $($rp.Name) to $xmlFile")
    $rp | Export-Clixml $xmlFile
  }
} elseif ($Import) {
  Get-ChildItem $FilePath | 
  Foreach-Object {
    $xmlFile = $_.FullName
    Write-Verbose("Importing: $xmlFile")
    if (!(Test-Path -path $xmlFile)) {
      "File not found" + $xmlFile
    } else {
      $rp = Import-Clixml -LiteralPath $xmlFile
      Import-ReplyingParty $rp
    }
  }
} 

