Function Get-TokenByUserPassword
{
	<#
	.SYNOPSIS
		Get OAuth access token using username and password.

	.EXAMPLE
		#Params
		$Credential = Get-Credential user@domain.pl
		$TenantId = "12345678-1234-1234-1234-1234567890ab"
		$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
		$Scope = "Mail.Send.Shared Mail.ReadWrite.Shared"
		$RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"

		#Token
		$AccessToken = Get-TokenByUserPassword -TenantId $TenantId -ApplicationId $ApplicationId -Credential $Credential -Scope $Scope -RedirectUri $RedirectUri
		$AccessToken

	.NOTES
		Author: Michal Gajda

	.LINK
		https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc#authorization-request
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)][String]$TenantId,
		[Parameter(Mandatory = $true)][String]$ApplicationId,
		[Parameter(Mandatory = $true)][PSCredential]$Credential,
		[Parameter()][String]$Scope = "https://graph.microsoft.com/.default",
		[Parameter(Mandatory = $true)][String]$RedirectUri
	)

	# Headers for the request
	$Headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }

	# Body parameters for the request
	$Body = @{
		client_id = $ApplicationId
		scope = $Scope
		username = $Credential.UserName
		password = $Credential.GetNetworkCredential().Password
		grant_type = "password"
		redirect_uri = $RedirectUri
	}

	# Token endpoint for the request
	$Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

	#Build the token request
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
