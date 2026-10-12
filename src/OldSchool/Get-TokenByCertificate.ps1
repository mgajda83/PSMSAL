Function Get-TokenByCertificate
{
	<#
	.SYNOPSIS
		Get OAuth access token using client certificate.

	.EXAMPLE
		#Params
		$Certificate = Get-PfxCertificate -FilePath ./Certificate.pfx
		$TenantId = "12345678-1234-1234-1234-1234567890ab"
		$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
		$Scope = "https://graph.microsoft.com/.default"

		#Token
		$AccessToken = Get-TokenByCertificate -Certificate $Certificate -TenantId $TenantId -ApplicationId $ApplicationId -Scope $Scope
		$AccessToken

	.NOTES
		Author: Michal Gajda

	.LINK
		https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)][String]$TenantId,
		[Parameter(Mandatory = $true)][String]$ApplicationId,
		[Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
		[Parameter()][String]$Scope = "https://graph.microsoft.com/.default"
	)

	#JWT params
	$CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

	$JWT_exp = [math]::Floor(((Get-Date) - ([datetime]::Parse("1970-01-01T00:00:00Z"))).TotalSeconds)
	$JWT_nbf = $JWT_exp + (10 * 60)

	#JWTHeader
	$JWTHeader = @{
		alg = "RS256"
		typ = "JWT"
		x5t = "$($CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '=')"
	} | ConvertTo-Json -Compress

	#JWTClaims
	$JWTClaims = @{
		aud = "https://login.microsoftonline.com/$TenantId/oauth2/token"
		exp = $JWT_exp
		iss = "$ApplicationId"
		jti = ([guid]::NewGuid()).Guid
		nbf = $JWT_nbf
		sub = "$ApplicationId"
	}  | ConvertTo-Json -Compress

	$StringList = @($JWTHeader, $JWTClaims)

	#JWT encoding
	$EncodedStringList = @()
	$StringList | ForEach-Object {
		$ClearTextString = $_
		# Convert supplied strings to base64
		$ClearTextBytes = [System.Text.Encoding]::UTF8.GetBytes($ClearTextString)
		$Base64EncodedString = [System.Convert]::ToBase64String($ClearTextBytes).Replace('=', '').Replace('+', '-').Replace('/', '_')
		$EncodedStringList += $Base64EncodedString
	}

	# Join header and Payload with "." to create a valid (unsigned) JWT
	$StringToSign = $EncodedStringList -join '.'

	# Get the private key object of your certificate
	$PrivateKey = $Certificate.PrivateKey

	# Define RSA signature and hashing algorithm
	$RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
	$HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

	# Create a signature of the JWT
	$Signature = [System.Convert]::ToBase64String($PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($StringToSign),$HashAlgorithm,$RSAPadding)).Replace('=', '').Replace('+', '-').Replace('/', '_')

	# Join the signature to the JWT with "."
	$JWT = $StringToSign + "." + $Signature

	# Headers for the request with JWT as Authorization
	$Headers = @{ Authorization = "Bearer $JWT" }

	# Create a hash with body parameters
	$Body = @{
		client_id = $ApplicationId
		client_assertion = $JWT
		client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		scope = $Scope
		grant_type = "client_credentials"
	}

	# Token endpoint for the request
	$Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

	# Build the token request
	$RequestParams = @{
		ContentType = 'application/x-www-form-urlencoded'
		Method = 'POST'
		Body = $Body
		Uri = $Uri
		Headers = $Headers
	}

	# Get the token
	$Response = Invoke-RestMethod @RequestParams

	Return $Response.access_token
}
