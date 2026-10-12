Function ConvertFrom-JWTToken
{
<#
	.SYNOPSIS
		Get JWT token information.

	.PARAMETER JWTToken
		AccessToken string.

	.PARAMETER ValidateSignature
		Use additional signature validation.

	.PARAMETER AsJSON
		Return data as json.

	.EXAMPLE
		$AccessToken | ConvertFrom-JWTToken -AsJSON

	.EXAMPLE
		$AccessToken | ConvertFrom-JWTToken -ValidateSignature

	.NOTES
		Author: Michal Gajda

	.LINK
		https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[string]$JWTToken,
		[Switch]$ValidateSignature,
		[Switch]$AsJSON
	)

	#Check if token is ok
	if (!$JWTToken.Contains(".") -or !$JWTToken.StartsWith("eyJ"))
	{
		Write-Error "Invalid Access Token" -ErrorAction Stop
	}

	$DecodedToken = @{}
	$Header, $Payload, $Signature = $JWTToken.Split(".")

	#Decode Header
	$HeaderData = $Header.Replace('-', '+').Replace('_', '/')
	while($HeaderData.Length % 4 -ne 0) { $HeaderData += "=" }
	$DecodedHeader = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($HeaderData)) | ConvertFrom-Json
	$DecodedToken['Header'] = [PSCustomObject]$DecodedHeader

	#Decode Payload
	$PayloadData = $Payload.Replace('-', '+').Replace('_', '/')
	while($PayloadData.Length % 4 -ne 0) { $PayloadData += "=" }
	$DecodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PayloadData)) | ConvertFrom-Json
	$DecodedToken['Payload'] = [PSCustomObject]$DecodedPayload

	#Get expiration time
	$UnixTime = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
	$UtcTime = $UnixTime.AddSeconds($DecodedToken['Payload'].exp)
	$ExpiryDateTime = $UtcTime.AddMinutes($(Get-TimeZone).GetUtcOffset($(Get-Date)).TotalMinutes)
	$DecodedToken['ExpiryDateTime'] = $ExpiryDateTime

	#Validation
	if($ValidateSignature)
	{
		$Issuer = $DecodedToken['Payload'].iss
		$Kid = $DecodedToken['Header'].kid

		#Get keys pool for tenant
		$Url = $Issuer + ".well-known/openid-configuration"
		#if($null -ne $AppId) { $Url += "?appid=" + $AppId }
		$Configuration = (ConvertFrom-Json (Invoke-WebRequest $Url).Content)
		$Keys = (ConvertFrom-Json (Invoke-WebRequest $Configuration.jwks_uri).Content).Keys
		$KeysHT = $Keys | Group-Object -Property Kid -AsHashTable

		#Get right key
		$Key = $KeysHT[$Kid]

		if($null -ne $Key)
		{
			#Get key info
			$KeyInfo = @{}
			$KeyInfo['e'] = $Key.e
			$KeyInfo['kty'] = $Key.kty
			$KeyInfo['n'] = $Key.n
			$KeyInfo['kid'] = $Key.kid

			#Decode public cert
			if($Key.x5c)
			{
				$X5C = $Key.x5c | Select-Object -First 1
				$X509Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($X5C))
				$KeyInfo['X509Certificate'] = $X509Certificate
			}
			$DecodedToken['KeyInfo'] = [PSCustomObject]$KeyInfo

			#Validate Signature
			$RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider
			$RSAParameters = [System.Security.Cryptography.RSAParameters]::New()

			$KaynData = $Key.n.Replace('-', '+').Replace('_', '/')
			while($KaynData.Length % 4 -ne 0) { $KaynData += "=" }
			$RSAParameters.Modulus = [Convert]::FromBase64String($KaynData)

			$KayeData = $Key.e.Replace('-', '+').Replace('_', '/')
			while($KayeData.Length % 4 -ne 0) { $KayeData += "=" }
			$RSAParameters.Exponent = [System.Convert]::FromBase64String($KayeData)

			$RSA.ImportParameters($RSAParameters)

			$SignatureDeformatter = [System.Security.Cryptography.RSAPKCS1SignatureDeformatter]::new($RSA)
			$SignatureDeformatter.SetHashAlgorithm("SHA256")

			#Get hash of header and payload
			$SHA256 = [System.Security.Cryptography.SHA256]::Create()
			$Hash = $SHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Header + '.' + $Payload))

			#Decode signature
			$SignatureData = $Signature.Replace('-', '+').Replace('_', '/')
			while($SignatureData.Length % 4 -ne 0) { $SignatureData += "=" }
			$SignatureBytes = [System.Convert]::FromBase64String($SignatureData)

			#Verify signature
			if($SignatureDeformatter.VerifySignature($Hash, $SignatureBytes))
			{
				$DecodedToken['SignatureStatus'] = "Signature Verified"
			} else
			{
				if($TokenClaims.aud -eq "https://graph.microsoft.com")
				{
					$DecodedToken['SignatureStatus'] = "Cant validate MSGraph token signature"
				} else
				{
					$DecodedToken['SignatureStatus'] = "Invalid Signature"
				}
			}
		}
	}

	if($AsJSON)
	{
		$Result = [PSCustomObject]$DecodedToken | ConvertTo-Json -Depth 5
	} else {
		$Result = [PSCustomObject]$DecodedToken
	}

	Return $Result
}
