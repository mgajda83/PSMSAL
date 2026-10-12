Function Get-TokenByDeviceCodeRequest
{
	<#
	.SYNOPSIS
		Get OAuth access token using device code - Request.

	.EXAMPLE
		#Params
		$TenantId = "12345678-1234-1234-1234-1234567890ab"
		$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
		$Scope = "Mail.Send.Shared Mail.ReadWrite.Shared"

		#Token
		$Request = Get-TokenByDeviceCodeRequest -TenantId $TenantId -ApplicationId $ApplicationId -Scope $Scope
		$Request

	.NOTES
		Author: Michal Gajda

	.LINK
		https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code#device-authorization-request
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)][String]$TenantId,
		[Parameter(Mandatory = $true)][String]$ApplicationId,
		[Parameter()][String]$Scope = "https://graph.microsoft.com/.default"
	)

	# Headers for the request
	$Headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }

	# Body parameters for the request
	$Body = @{
		client_id = $ApplicationId
		scope = $Scope
	}

	# Token endpoint for the request
	$Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"

	# Build the token request
	$RequestParams = @{
		Uri = $Uri
		Headers = $Headers
		Method = "POST"
		Body = $Body
	}

	# Get the token
	$Response = Invoke-RestMethod @RequestParams
	Write-Host $Response.message -ForegroundColor Cyan

	Return $Response.device_code
}


Function Get-TokenByDeviceCodeResponse
{
	<#
	.SYNOPSIS
		Get OAuth access token using device code - Response.

	.EXAMPLE
		#Params
		$TenantId = "12345678-1234-1234-1234-1234567890ab"
		$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
		$DeviceCode = "Device Code returned by Get-TokenByDeviceCodeRequest"

		#Token
		$AccessToken = Get-TokenByDeviceCodeResponse -TenantId $TenantId -ApplicationId $ApplicationId -DeviceCode $DeviceCode
		$AccessToken

	.NOTES
		Author: Michal Gajda

	.LINK
		https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code#device-authorization-response
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)][String]$TenantId,
		[Parameter(Mandatory = $true)][String]$ApplicationId,
		[Parameter(Mandatory = $true)][String]$DeviceCode
	)

	# Headers for the request
	$Headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }

	# Body parameters for the request
	$Body = @{
		grant_type = "urn:ietf:params:oauth:grant-type:device_code"
		client_id = $ApplicationId
		device_code = $DeviceCode
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

	Return $Response.message
}
