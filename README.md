# PSMSAL
[![PSGallery Version](https://img.shields.io/powershellgallery/v/PSMSAL.svg?style=flat&logo=powershell&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/PSMSAL) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/PSMSAL.svg?style=flat&logo=powershell&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/PSMSAL) [![PowerShell](https://img.shields.io/badge/PowerShell-5.1-blue?style=flat&logo=powershell)](https://www.powershellgallery.com/packages/PSMSAL) [![PSGallery Platform](https://img.shields.io/powershellgallery/p/PSMSAL.svg?style=flat&logo=powershell&label=PSGallery%20Platform)](https://www.powershellgallery.com/packages/PSMSAL)

PowerShell module to generate authentication tokens in Entra ID

## Get-PSMSALToken (only on PS7+)
### Token with Graph application permission using certificate
```
$Params = @{
    ClientId = $ApplicationId
    TenantId = $TenantId
    RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    Certificate = $Certificate
    AsSecureString = $true
}
$Token = Get-PSMSALToken @Params

Connect-MgGraph -AccessToken $Token.SecureAccessToken -NoWelcome
```

### Token with Graph delegated permission using user credential
```
$Params = @{
	Scopes = @("https://graph.microsoft.com/.default")
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	ClientId = $ApplicationId
	TenantId = $TenantId
	Credential = $Credential
	AsSecureString = $true
}
$Token = Get-PSMSALToken @Params

Connect-MgGraph -AccessToken $Token.SecureAccessToken -NoWelcome
```

### Token with specific Graph delegated permission using user credential
```
$Params = @{
	Scopes = @("Mail.Send.Shared","Mail.ReadWrite.Shared")
	ClientId = $ApplicationId
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Credential = $Credential
	Authority = "AzureAdMultipleOrgs"
	AsSecureString = $true
}
$Token = Get-PSMSALToken @Params

Connect-MgGraph -AccessToken $Token.SecureAccessToken -NoWelcome
```

### Token with ExchangeOnline permission as App
```
$Params = @{
	Scopes = @("https://outlook.office365.com/.default")
	ClientId = $Connection.ApplicationId
	TenantId = $Connection.TenantId
	Certificate = $Certificate
}
$Token = Get-PSMSALToken @Params

Connect-ExchangeOnline -AccessToken $Token.AccessToken -Organization $Connection.TenantId
```

### Token with Exchange EWS permission using user credential
```
$Params = @{
	Scopes = @("https://outlook.office365.com/.default")
	ClientId = $ApplicationId
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Credential = $Credential
	Authority = "AzureAdMultipleOrgs"
	AsSecureString = $true
}
$Token = Get-PSMSALToken @Params
```

### Token with application Defender permission
```
$Params = @{
	Scopes = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
	Certificate = $Certificate
	TenantId = $TenantId
	ClientId = $ApplicationId
	AzureCloudInstance = "AzurePublic"
}
$Token = Get-PSMSALToken @Params
```

### Token with Teams permission as User
```
#Graph
$Params = @{
	Scopes = @("https://graph.microsoft.com/.default")
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	ClientId = $ApplicationId
	TenantId = $TenantId
	Credential = $Credential
}
$GraphToken_MSAL = Get-PSMSALToken @Params

#Teams
$Params = @{
	Scopes = @("48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default")
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	ClientId = $ApplicationId
	TenantId = $TenantId
	Credential = $Credential
}
$TeamsToken_MSAL = Get-PSMSALToken @Params

Connect-MicrosoftTeams -AccessTokens @($GraphToken_MSAL.AccessToken, $TeamsToken_MSAL.AccessToken)
```

### Token with specific SharePoint as App
```
$Params = @{
	Scopes = @($Scope)
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	ClientId = $ApplicationId
	TenantId = $TenantId
	Certificate = $Certificate
	AzureCloudInstance = "AzurePublic"
}
$Token = Get-PSMSALToken @Params

Connect-PnPOnline -Url $SiteUrl -AccessToken $Token.AccessToken
```

### Token with specific SharePoint permission as User
```
$Params = @{
	Scope = @("Sites.ReadWrite.All","Files.ReadWrite.All")
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Credential = $Credential
	ClientId = $ApplicationId
	TenantId = $TenantId
	AsSecureString = $true
}
$Token = Get-PSMSALToken @Params

Connect-MgGraph -AccessToken $Token.SecureAccessToken -NoWelcome
```

### Token with Azure permission as App
```
$Params = @{
	Scopes = @("https://management.azure.com/.default")
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Certificate = $Certificate
	TenantId = $TenantId
	ClientId = $ApplicationId
	AzureCloudInstance = "AzurePublic"
}
$Token = Get-PSMSALToken @Params

Connect-AzAccount -AccessToken $Token.AccessToken -AccountId $Connection.ApplicationId
```

#### Token with ChatBot API permission as App
```
$Params = @{
	Scopes = @("https://api.botframework.com/.default")
	RedirectUri = "https://localhost"
	Secret = $Secret
	TenantId = $TenantId
	ClientId = $ApplicationId
	AzureCloudInstance = "AzurePublic"
}
$Token = Get-PSMSALToken @Params
```

#### Token with Storage Account permission
```
$Params = @{
	Scope = @("https://storage.azure.com/.default")
	ClientId = $ApplicationId
	TenantId = $TenantId
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Certificate = $Certificate
}
$Token = Get-PSMSALToken @Params
```

#### Token with Service Bus permission
```
$Params = @{
	Scope = @("https://servicebus.azure.net/.default")
	ClientId = $ApplicationId
	TenantId = $TenantId
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Certificate = $Certificate
}
$Token = Get-PSMSALToken @Params
```

#### Token with Key Vault permission
```
$Params = @{
	Scope = @("https://vault.azure.net/.default")
	ClientId = $ApplicationId
	TenantId = $TenantId
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Certificate = $Certificate
}
$Token = Get-PSMSALToken @Params
```

#### Token with Event Hub permission
```
$Params = @{
	Scope = @("https://eventhubs.azure.net/.default")
	ClientId = $ApplicationId
	TenantId = $TenantId
	RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
	Certificate = $Certificate
}
$Token = Get-PSMSALToken @Params
```

#### Token with Log Analytics permission
```
$Params = @{
	Scopes = 'https://monitor.azure.com/.default'
	Certificate = $Certificate
	TenantId = $TenantId
	ClientId = $ClientId
	AzureCloudInstance = "AzurePublic"
}
$Token = Get-PSMSALToken @Params
```

## Old school way (On PS5.1)
#### Token with application permission by secret
```
$Token = Get-TokenBySecret -ClientId $ApplicationID -TenantId $TenantID -Secret $Secret
```

#### Token with application permission by certificate
```
$Token = Get-TokenByCertificate -ClientId $ApplicationID -TenantId $TenantID -Certificate $Certificate
```

#### Token with user permission by credential
```
$Token = Get-TokenByUserPassword -ClientId $ApplicationID -TenantId $TenantID -Credential $Credential
```

#### Token with user permission by device code
```
#Step 1
$DeviceCode = Get-TokenByDeviceCodeRequest -ClientId $ApplicationID -TenantId $TenantID

#Step 2
$Token = Get-TokenByDeviceCodeResponse -ClientId $ApplicationID -TenantId $TenantID -DeviceCode $DeviceCode
```

#### Decode JWT token
```
$Token | ConvertFrom-JWTToken -ShowAsJson
```
