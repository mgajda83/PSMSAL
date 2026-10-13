using System;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net.Http;

namespace PSMSAL
{
    /// <summary>
    /// <para type="synopsis">Get OAuth access token using client certificate.</para>
    /// </summary>

    /// <example>
    /// <code>
    /// <para>Get token by app certificate.</para>
    ///
    /// $Certificate = Get-PfxCertificate -FilePath ./Certificate.pfx
	///	$TenantId = "12345678-1234-1234-1234-1234567890ab"
	///	$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
	///	$Scope = 'https://graph.microsoft.com/.default'
    ///
	///	#Token
	///	$AccessToken = Get-TokenByCertificate -Certificate $Certificate -TenantId $TenantId -ApplicationId $ApplicationId -Scope $Scope
	///	$AccessToken
    /// </code>
    /// </example>


    [Cmdlet(VerbsCommon.Get,"TokenByCertificate")]
    public class GetTokenByCertificateCmdletCommand : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Application ID.</para>
        /// </summary>
        [Alias("ApplicationId")]
        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true)]
        public string ClientId { get; set; }

        /// <summary>
        /// <para type="description">Tenant ID.</para>
        /// </summary>
        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true)]
        public string TenantId { get; set; }

        /// <summary>
        /// <para type="description">Scopes list.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public string[] Scopes { get; set; } = new string[1] {"https://graph.microsoft.com/.default"};

        /// <summary>
        /// <para type="description">Use certificate authentication.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// <para type="description">Set output format.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        [ValidateSet("Token", "Json", "Object")]
        public string Output { get; set; } = "Token";

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Begin Get-TokenByCertificate!");
            //WriteVerbose(this.ParameterSetName);
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
            //JWT params
            var CertificateBase64Hash = Convert.ToBase64String(Certificate.GetCertHash());

            var JWT_exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
            var JWT_nbf = JWT_exp + (10 * 60);

            //JWTHeader
            var JWTHeader = new Dictionary<string, object>
            {
                { "alg", "RS256" },
                { "typ", "JWT" },
                { "x5t", CertificateBase64Hash.Replace("+", "-").Replace("/", "_").TrimEnd('=') }
            };
            var JWTHeaderJson = JsonSerializer.Serialize(JWTHeader);

            //JWTClaims
            var JWTClaims = new Dictionary<string, object>
            {
                { "aud", $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token" },
                { "exp", JWT_exp },
                { "iss", ClientId },
                { "jti", Guid.NewGuid().ToString() },
                { "nbf", JWT_nbf },
                { "sub", ClientId }
            };
            var JWTClaimsJson = JsonSerializer.Serialize(JWTClaims);
            var StringList = new List<string> { JWTHeaderJson, JWTClaimsJson };

            //JWT encoding
            var EncodedStringList = new List<string>();
            foreach (var str in StringList)
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(str);
                var base64 = Convert.ToBase64String(bytes);
                var base64Url = base64.Replace("+", "-").Replace("/", "_").TrimEnd('=');
                EncodedStringList.Add(base64Url);
            }
            //Join header and Payload with "." to create a valid (unsigned) JWT
            var StringToSign = string.Join(".", EncodedStringList);

            //Get the private key object of your certificate
            var PrivateKey = Certificate.GetRSAPrivateKey();

            //Define RSA signature and hashing algorithm
            var RSAPadding = System.Security.Cryptography.RSASignaturePadding.Pkcs1;
            var HashAlgorithm = System.Security.Cryptography.HashAlgorithmName.SHA256;

            //Create a signature of the JWT
            var SignatureBytes = PrivateKey.SignData(System.Text.Encoding.UTF8.GetBytes(StringToSign), HashAlgorithm, RSAPadding);

            //Join the signature to the JWT with "."
            var JWT = StringToSign + "." + Convert.ToBase64String(SignatureBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');

            //Send the request to the token endpoint
            var tokenUrl = $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token";

            var parameters = new Dictionary<string, string>
            {
                { "address", tokenUrl },
                { "client_id", ClientId },
                { "client_assertion", JWT },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "grant_type", "client_credentials" },
                { "scope", string.Join(" ", Scopes) }
            };
            WriteVerbose("Sending request to token endpoint: " + tokenUrl);
            WriteVerbose("client_id: " + parameters["client_id"]);
            WriteVerbose("grant_type: " + parameters["grant_type"]);
            WriteVerbose("client_assertion_type: " + parameters["client_assertion_type"]);
            WriteVerbose("scope: " + parameters["scope"]);

            var httpClient = new HttpClient();
            var processRecordInBackground = Task
                .Run(async () => await this.HttpClientRequest(httpClient, tokenUrl, parameters, JWT));

            // await the finalization of the BG task
            var result = processRecordInBackground.GetAwaiter().GetResult();
            var tokenParse = JsonNode.Parse(result);
            var accessToken = tokenParse["access_token"]?.ToString();

            // if access token is null or empty then throw error with error_description and error from tokenParse
            if(string.IsNullOrEmpty(accessToken))
            {
                WriteError(new ErrorRecord(
                    new ArgumentException(tokenParse["error_description"]?.ToString()),
                    tokenParse["error"]?.ToString(),
                    ErrorCategory.InvalidArgument,
                    null));
                return;
            }

            // return result;
            // as access token
            if(Output == "Token")
            {
                WriteObject(accessToken);
            }
            // as json
            if(Output == "Json")
            {
                var tokenJson = JsonSerializer.Serialize(tokenParse, new JsonSerializerOptions { WriteIndented = true });
                WriteObject(tokenJson);
            }
            // as object
            if(Output == "Object")
            {
                var tokenObject = new PSObject();
                foreach (var property in tokenParse.AsObject())
                {
                    tokenObject.Properties.Add(new PSNoteProperty(property.Key, property.Value.ToString()));
                }
                WriteObject(tokenObject);
            }
        }

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            WriteVerbose("End!");
        }

        public async Task<string> HttpClientRequest(HttpClient client, string url, Dictionary<string, string> parameters, string JWT)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Authorization", $"Bearer {JWT}");
            request.Content = new FormUrlEncodedContent(parameters);
            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();

            return responseString;
        }
    }
}
