using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace PSMSAL
{
    /// <summary>
    /// <para type="synopsis">Generate token via MSAL library.</para>
    /// <para type="description">PowerShell module to generate authentication tokens in Entra ID.</para>
    /// </summary>

    /// <example>
    /// <code>
    /// <para>Get token by user credential.</para>
    ///
    /// $Credential = Get-Credential
    /// $Token = Get-PSMSALToken -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -Credential $Credential -RedirectUri "https://login.microsoftonline.com/common/oauth2/nativeclient" -Authority AzureAdMultipleOrgs
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get token by DeviceCode.</para>
    ///
    /// $Token = Get-PSMSALToken -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -DeviceCode
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get token by interactive logon.</para>
    ///
    /// $Token = Get-PSMSALToken -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -Interactive
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get token by certificate.</para>
    ///
    /// $Certificate = Get-PfxCertificate -FilePath /Users/mgajda/cert.pfx
    /// $Token = Get-PSMSALToken -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -Certificate $Certificate
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get token by secret.</para>
    ///
    /// $Token = Get-PSMSALToken -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -Secret xyz
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get delegated graph token to send email from shared mailbox.</para>
    ///
    /// $Params = @{
    ///     Scopes = @("Mail.Send.Shared","Mail.ReadWrite.Shared")
    ///     ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ///     RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    ///     UserCredential = $Credential
    ///     Authority = "AzureAdMultipleOrgs"
    ///     AsSecureString = $true
    /// }
    /// $Token = Get-PSMSALToken @Params
    ///
    /// Connect-MgGraph -AccessToken $Token.AsSecureString
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get WindowsDefenderAPI token.</para>
    ///
    /// $Params = @{
    ///     Scopes = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
    ///     Certificate = $Certificate
    ///     TenantId = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    ///     ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ///     AzureCloudInstance = "AzurePublic"
    /// }
    /// $Token = Get-PSMSALToken @Params
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get Microsoft Teams API token.</para>
    ///
    /// $Params = @{
    /// 	Scopes = @("https://graph.microsoft.com/.default")
    ///     RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    ///     TenantId = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    ///     ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ///     Credential = $Credential
    /// }
    /// $GraphToken = Get-PSMSALToken @Params
    ///
    /// $Params = @{
    /// 	Scopes = @("48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default")
    ///     RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    ///     TenantId = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    ///     ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ///     Credential = $Credential
    /// }
    /// $TeamsToken = Get-PSMSALToken @Params
    ///
    /// Connect-MicrosoftTeams -AccessTokens @($GraphToken.AccessToken, $TeamsToken.AccessToken)
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get Azure token as app.</para>
    ///
    /// $Params = @{
	///     Scopes = @("https://management.azure.com/.default")
    ///     RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    ///     Certificate = $Certificate
    ///     TenantId = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    ///     ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ///     AzureCloudInstance = "AzurePublic"
    /// }
    /// $Token = Get-PSMSALToken @Params
    ///
    /// Connect-AzAccount -AccessToken $Token.AccessToken -AccountId $Connection.ApplicationId
    ///
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get Exchange Online token as app.</para>
    ///
    ///$Params = @{
    ///     Scopes = @("https://outlook.office365.com/.default")
    ///     TenantId = "yyyyyyyy.onmicrosoft.com"
    ///     ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ///     Certificate = $Certificate
    /// }
    /// $Token = Get-PSMSALToken @Params
    ///
    /// Connect-ExchangeOnline -AccessToken $Token.AccessToken -Organization yyyyyyyy.onmicrosoft.com
    ///
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get Bot framework token.</para>
    ///
    /// $Params = @{
    /// 	Scopes = @("https://api.botframework.com/.default")
    /// 	RedirectUri = "https://localhost"
    /// 	Secret = "xyz"
    /// 	TenantId = "yyyyyyyy.onmicrosoft.com"
    /// 	ClientId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    /// 	AzureCloudInstance = "AzurePublic"
    /// }
    /// $Token = Get-PSMSALToken @Params
    ///
    /// </code>
    /// </example>

    [Cmdlet(VerbsCommon.Get,"PSMSALToken",DefaultParameterSetName="Public")]
    [OutputType(typeof(Microsoft.Identity.Client.AuthenticationResult))]
    public class GetPSMSALTokenCmdletCommand : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Application ID.</para>
        /// </summary>
        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true)]
        public string ClientId { get; set; }

        /// <summary>
        /// <para type="description">Tenant ID.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public string TenantId { get; set; }

        /// <summary>
        /// <para type="description">Redirect URI.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public string RedirectUri { get; set; } = "https://login.microsoftonline.com/common/oauth2/nativeclient";

        /// <summary>
        /// <para type="description">Authority, accept one of: AzureAdMyOrg or AzureAdMultipleOrgs.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        [ValidateSet("AzureAdMyOrg", "AzureAdMultipleOrgs")]
        public string Authority { get; set; }

        /// <summary>
        /// <para type="description">AzureCloudInstance, accept one of: AzurePublic, AzureUsGovernment, AzureGermany or AzureChina. Require also TenantId.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        [ValidateSet("AzureChina","AzureGermany","AzurePublic","AzureUsGovernment")]
        public string AzureCloudInstance { get; set; }

        /// <summary>
        /// <para type="description">Scopes list.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public string[] Scopes { get; set; } = new string[1] {"https://graph.microsoft.com/.default"};

        /// <summary>
        /// <para type="description">User credential.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Public-AcquireTokenByUsernamePassword")]
        public PSCredential Credential { get; set; }

        /// <summary>
        /// <para type="description">Use devicecode authentication.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Public-AcquireTokenWithDeviceCode")]
        public SwitchParameter DeviceCode { get; set; }

        /// <summary>
        /// <para type="description">Use interactive authentication.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Public-AcquireTokenInteractive")]
        public SwitchParameter Interactive { get; set; }

        /// <summary>
        /// <para type="description">Use certificate authentication.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Confidential-WithCertificate")]
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// <para type="description">Use secret authentication.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Confidential-WithClientSecret")]
        public string Secret { get; set; }

        /// <summary>
        /// <para type="description">Add SecureString token.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public SwitchParameter AsSecureString { get; set; }

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Begin!");
            WriteVerbose(this.ParameterSetName);
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
            //Initialize result
            AuthenticationResult Token = null;

            //Public application
            if(this.ParameterSetName.StartsWith("Public-"))
            {
                //Create application builder
                WriteVerbose("Public application buider");
                var ClientApplicationBuilder = PublicClientApplicationBuilder.Create(ClientId);

                //Set Authority
                if(this.MyInvocation.BoundParameters.ContainsKey("Authority"))
                {
                    WriteVerbose("WithAuthority");
                    switch(Authority)
                    {
                        case "AzureAdMyOrg":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AadAuthorityAudience.AzureAdMyOrg);
                            break;
                        case "AzureAdMultipleOrgs":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AadAuthorityAudience.AzureAdMultipleOrgs);
                            break;
                    }
                }

                //Set AzureCloudInstance
                if(this.MyInvocation.BoundParameters.ContainsKey("AzureCloudInstance"))
                {
                    WriteVerbose("WithAuthority-AzureCloudInstance");
                    switch(AzureCloudInstance)
                    {
                        case "AzurePublic":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzurePublic,TenantId);
                            break;
                        case "AzureUsGovernment":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzureUsGovernment,TenantId);
                            break;
                        case "AzureGermany":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzureGermany,TenantId);
                            break;
                        case "AzureChina":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzureChina,TenantId);
                            break;
                    }
                }

                //Set RedirectUri
                if(this.MyInvocation.BoundParameters.ContainsKey("RedirectUri"))
                {
                    WriteVerbose("WithRedirectUri");
                    ClientApplicationBuilder.WithRedirectUri(RedirectUri);
                }

                //Set TenantId
                if(this.MyInvocation.BoundParameters.ContainsKey("TenantId"))
                {
                    WriteVerbose("WithTenantId");
                    ClientApplicationBuilder.WithTenantId(TenantId);
                }

                //Build application
                IPublicClientApplication ClientApplication = ClientApplicationBuilder.Build();

                //Set Scopes
                IEnumerable<string> ScopeLists = Scopes;

                //AcquireTokenByUsernamePassword
                if(this.ParameterSetName == "Public-AcquireTokenByUsernamePassword")
                {
                    WriteVerbose("AcquireTokenByUsernamePassword");
                    Token = ClientApplication.AcquireTokenByUsernamePassword(ScopeLists,Credential.UserName,Credential.Password).ExecuteAsync().Result;
                }

                //AcquireTokenWithDeviceCode
                if(this.ParameterSetName == "Public-AcquireTokenWithDeviceCode")
                {
                    WriteVerbose("AcquireTokenWithDeviceCode");
                    Token = ClientApplication.AcquireTokenWithDeviceCode(ScopeLists,deviceCodeResult =>
                    {
                        Console.WriteLine(deviceCodeResult.Message);
                        return Task.FromResult(0);
                    }).ExecuteAsync().Result;
                }

                //AcquireTokenInteractive
                if(this.ParameterSetName == "Public-AcquireTokenInteractive")
                {
                    WriteVerbose("AcquireTokenInteractive");
                    Token = ClientApplication.AcquireTokenInteractive(ScopeLists).ExecuteAsync().Result;
                }

            } else {
                WriteVerbose("Confidential application buider");
                var ClientApplicationBuilder = ConfidentialClientApplicationBuilder.Create(ClientId);

                //Set Authority
                if(!(String.IsNullOrEmpty(Authority)))
                {
                    WriteVerbose("WithAuthority");
                    switch(Authority)
                    {
                        case "AzureAdMyOrg":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AadAuthorityAudience.AzureAdMyOrg);
                            break;
                        case "AzureAdMultipleOrgs":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AadAuthorityAudience.AzureAdMultipleOrgs);
                            break;
                    }
                }

                //Set AzureCloudInstance
                if(this.MyInvocation.BoundParameters.ContainsKey("AzureCloudInstance"))
                {
                    WriteVerbose("WithAuthority-AzureCloudInstance");
                    switch(AzureCloudInstance)
                    {
                        case "AzurePublic":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzurePublic,TenantId);
                            break;
                        case "AzureUsGovernment":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzureUsGovernment,TenantId);
                            break;
                        case "AzureGermany":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzureGermany,TenantId);
                            break;
                        case "AzureChina":
                            ClientApplicationBuilder.WithAuthority(Microsoft.Identity.Client.AzureCloudInstance.AzureChina,TenantId);
                            break;
                    }
                }

                //Set RedirectUri
                if(this.MyInvocation.BoundParameters.ContainsKey("RedirectUri"))
                {
                    WriteVerbose("WithRedirectUri");
                    ClientApplicationBuilder.WithRedirectUri(RedirectUri);
                }

                //Set TenantId
                if(this.MyInvocation.BoundParameters.ContainsKey("TenantId"))
                {
                    WriteVerbose("WithTenantId");
                    ClientApplicationBuilder.WithTenantId(TenantId);
                }

                //Set Certificate
                if(this.MyInvocation.BoundParameters.ContainsKey("Certificate"))
                {
                    WriteVerbose("WithCertificate");
                    ClientApplicationBuilder.WithCertificate(Certificate);
                }

                //Set Secret
                if(this.MyInvocation.BoundParameters.ContainsKey("Secret"))
                {
                    WriteVerbose("WithClientSecret");
                    ClientApplicationBuilder.WithClientSecret(Secret);
                }

                //Build application
                IConfidentialClientApplication ClientApplication = ClientApplicationBuilder.Build();

                //Set Scopes
                IEnumerable<string> ScopeLists = Scopes;

                //AcquireTokenForClient - WithCertificate
                if(this.MyInvocation.BoundParameters.ContainsKey("Certificate"))
                {
                    WriteVerbose("AcquireTokenForClient-WithCertificate");
                    Token = ClientApplication.AcquireTokenForClient(ScopeLists).ExecuteAsync().Result;
                }

                //AcquireTokenForClient - WithClientSecret
                if(this.MyInvocation.BoundParameters.ContainsKey("Secret"))
                {
                    WriteVerbose("AcquireTokenForClient-WithClientSecret");
                    Token = ClientApplication.AcquireTokenForClient(ScopeLists).ExecuteAsync().Result;
                }
            }

            //Return token
            if(AsSecureString)
            {
                WriteVerbose("AsSecureString");
                SecureString AccessToken = new SecureString();
                Array.ForEach(Token.AccessToken.ToCharArray(), AccessToken.AppendChar);
                AccessToken.MakeReadOnly();

                var PSToken = new PSObject(Token);
                PSToken.Properties.Add(new PSNoteProperty("AsSecureString", AccessToken));
                WriteObject(PSToken);
                //WriteObject(AccessToken);
            } else {
                WriteObject(Token);
            }

        }

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            WriteVerbose("End!");
        }
    }
}
