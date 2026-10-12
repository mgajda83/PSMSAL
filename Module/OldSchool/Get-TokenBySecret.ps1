Function Get-TokenBySecret
{
	<#
	.SYNOPSIS
		Get OAuth access token using client secret.

	.EXAMPLE
		#Params
		$Secret = "12345~"
		$TenantId = "12345678-1234-1234-1234-1234567890ab"
		$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
		$Scope = "https://graph.microsoft.com/.default"

		#Token
		$AccessToken = Get-TokenBySecret -TenantId $TenantId -ApplicationId $ApplicationId -Secret $Secret -Scope $Scope
		$AccessToken

	.NOTES
		Author: Michal Gajda

	.LINK
		https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#first-case-access-token-request-with-a-shared-secret
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)][String]$TenantId,
		[Parameter(Mandatory = $true)][String]$ApplicationId,
		[Parameter(Mandatory = $true)][String]$Secret,
		[Parameter()][String]$Scope = "https://graph.microsoft.com/.default"
	)

	# Headers for the request
	$Headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }

	# Body parameters for the request
	$Body = @{
		client_id = $ApplicationId
		scope = $Scope
		client_secret = $Secret
		grant_type = "client_credentials"
	}

	# Token endpoint for the request
	$Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

	# Build the token request
	$RequestParams = @{
		Uri = $Uri
		Headers = $Headers
		Method = "POST"
		Body = $Body
	}

	# Get the token
	$Response = Invoke-RestMethod @RequestParams

	Return $Response.access_token
}
