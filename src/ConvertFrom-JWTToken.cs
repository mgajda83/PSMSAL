using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Net.Http;


namespace PSMSAL
{
    /// <summary>
    /// <para type="synopsis">Get JWT token information.</para>
    /// <para type="description">PowerShell module to generate authentication tokens in Entra ID.</para>
    /// </summary>

    /// <example>
    /// <code>
    /// <para>Get token detail as JSON.</para>
    ///
    /// $AccessToken | ConvertFrom-JWTToken -AsJSON
    /// </code>
    /// </example>

    /// <example>
    /// <code>
    /// <para>Get token detail and validate its signature.</para>
    ///
    /// $AccessToken | ConvertFrom-JWTToken -ValidateSignature
    /// </code>
    /// </example>

    [Cmdlet("ConvertFrom","JWTToken")]
    public class ConvertFromJWTTokenCmdletCommand : PSCmdlet
    {
        /// <summary>
        /// <para type="description">JWT token.</para>
        /// </summary>
        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true)]
        public string JWTToken { get; set; }

         /// <summary>
        /// <para type="description">Validate the token signature.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public SwitchParameter ValidateSignature { get; set; }

        /// <summary>
        /// <para type="description">Output as JSON.</para>
        /// </summary>
        [Parameter(
            ValueFromPipelineByPropertyName = true)]
        public SwitchParameter ShowAsJson { get; set; }

        //Global variables
        private static Helpers helpers { get; set; } = new Helpers();

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Begin ConvertFrom-JWTToken!");
            //WriteVerbose(this.ParameterSetName);
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
            // Validate the JWT token format
            if(JWTToken.Split('.').Length != 3)
            {
                WriteError(new ErrorRecord(
                    new ArgumentException("Invalid JWT token format."),
                    "InvalidJWTTokenFormat",
                    ErrorCategory.InvalidArgument,
                    JWTToken));
                return;
            }

            if(!JWTToken.StartsWith("eyJ"))
            {
                WriteError(new ErrorRecord(
                    new ArgumentException("Invalid JWT token format."),
                    "InvalidJWTTokenFormat",
                    ErrorCategory.InvalidArgument,
                    JWTToken));
                return;
            }

            // Initialize DecodedToken
            var DecodedToken = new PSObject();

            // Split the JWT token into its three parts
            var header = JWTToken.Split('.')[0];
            var payload = JWTToken.Split('.')[1];
            var signature = JWTToken.Split('.')[2];

            //Decode Header
            var decodedHeaderJSON = helpers.DecodePartToken(header);
            var decodedHeader = JsonNode.Parse(decodedHeaderJSON);
            var headerObject = new PSObject();
            foreach (var property in decodedHeader.AsObject())
            {
                headerObject.Properties.Add(new PSNoteProperty(property.Key, property.Value.ToString()));
            }
            DecodedToken.Properties.Add(new PSNoteProperty("Header", headerObject));

            //Decode Payload
            var decodedPayloadJSON = helpers.DecodePartToken(payload);
            var decodedPayload = JsonNode.Parse(decodedPayloadJSON);
            var payloadObject = new PSObject();
            foreach (var property in decodedPayload.AsObject())
            {
                payloadObject.Properties.Add(new PSNoteProperty(property.Key, property.Value.ToString()));
            }
            DecodedToken.Properties.Add(new PSNoteProperty("Payload", payloadObject));

            //Get expiration time
            var expiryDateTime = helpers.GetExpirationTime(decodedPayload["exp"].GetValue<long>());
            DecodedToken.Properties.Add(new PSNoteProperty("ExpirationTime", expiryDateTime));

            var signatureStatus = "Not Validated";
            if(ValidateSignature)
            {
                //Get tenant configurations
                var configurationUrl = $"{decodedPayload["iss"].ToString()}.well-known/openid-configuration";
                WriteVerbose("Configuration URL: " + configurationUrl);

                var httpClient = new HttpClient();
                var processRecordInBackgroundConfig = Task
                    .Run(async () => await this.HttpClientRequest(httpClient, configurationUrl));

                // await the finalization of the BG task
                var configurationResponseString = processRecordInBackgroundConfig.GetAwaiter().GetResult();
                var configurationParse = JsonNode.Parse(configurationResponseString);

                //Get keys
                var keysUrl = configurationParse["jwks_uri"]?.ToString();
                WriteVerbose("Keys URL: " + keysUrl);

                var processRecordInBackgroundKeys = Task
                    .Run(async () => await this.HttpClientRequest(httpClient, keysUrl));

                // await the finalization of the BG task
                var keysResponseString = processRecordInBackgroundKeys.GetAwaiter().GetResult();
                var keysParse = JsonNode.Parse(keysResponseString);

                var keys = keysParse["keys"]?.AsArray();

                var headerKid = decodedHeader["kid"]?.ToString();
                WriteVerbose("Header KID: " + headerKid);
                var keyJson = "";
                foreach(var key in keys)
                {
                    if(key["kid"]?.ToString() == headerKid)
                    {
                        keyJson = JsonSerializer.Serialize(key, new JsonSerializerOptions { WriteIndented = true });
                        break;
                    }
                }

                // if found key
                var keyInfo = new PSObject();
                if(!string.IsNullOrEmpty(keyJson))
                {
                    var keyParse = JsonNode.Parse(keyJson);
                    foreach (var property in keyParse.AsObject())
                    {
                        keyInfo.Properties.Add(new PSNoteProperty(property.Key, property.Value.ToString()));
                    }

                    var x5c = JsonNode.Parse(keyParse["x5c"]?.ToString())[0].ToString();
                    WriteVerbose("X5C: " + x5c);

                    X509Certificate2 X509Certificate = new X509Certificate2(Convert.FromBase64String(x5c));
                    keyInfo.Properties.Add(new PSNoteProperty("X509Certificate", X509Certificate));
                    DecodedToken.Properties.Add(new PSNoteProperty("KeyInfo", keyInfo));

                    //Validate Signature
                    var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
                    var rsaParameters = new System.Security.Cryptography.RSAParameters();

                    var keyNData = helpers.DecodePartTokenToBytes(keyParse["n"]?.ToString());
                    rsaParameters.Modulus = keyNData;

                    var keyEData = helpers.DecodePartTokenToBytes(keyParse["e"]?.ToString());
                    rsaParameters.Exponent = keyEData;

                    rsa.ImportParameters(rsaParameters);

                    var signatureDeformatter = new System.Security.Cryptography.RSAPKCS1SignatureDeformatter(rsa);
                    signatureDeformatter.SetHashAlgorithm("SHA256");

                    var sha256 = System.Security.Cryptography.SHA256.Create();
                    var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(header + "." + payload));

                    var signatureBytes = helpers.DecodePartTokenToBytes(signature);

                    if(signatureDeformatter.VerifySignature(hash,signatureBytes))
                    {
                        signatureStatus = "Signature Verified";
                    }
                    else
                    {
                        signatureStatus = "Cant validate token signature";
                        WriteVerbose("Audience: " + decodedPayload["aud"]?.ToString());
                    }
                    DecodedToken.Properties.Add(new PSNoteProperty("SignatureStatus", signatureStatus));
                }
            }

            if(ShowAsJson)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(decodedHeaderJSON);
                Console.ResetColor();

                Console.Write(".");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(decodedPayloadJSON);
                Console.ResetColor();

                Console.Write(".");
                switch(signatureStatus)
                {
                    case "Signature Verified":
                        Console.ForegroundColor = ConsoleColor.Green;
                        break;
                    case "Cant validate token signature":
                        Console.ForegroundColor = ConsoleColor.Red;
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Gray;
                        break;
                }
                Console.Write("["+ signatureStatus +"]");
                Console.ResetColor();
            }
            WriteObject(DecodedToken);
        }

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            WriteVerbose("End!");
        }

        public async Task<string> HttpClientRequest(HttpClient client, string url)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json");
            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();

            return responseString;
        }

       public async Task<string> RequestValidateSignature(HttpClient client, string configurationUrl, string headerKid)
        {
            //Get tenant configurations
            var configurationRequest = new HttpRequestMessage(HttpMethod.Get, configurationUrl);
            configurationRequest.Headers.Add("Accept", "application/json");
            var configurationResponse = await client.SendAsync(configurationRequest);
            var configurationResponseString = await configurationResponse.Content.ReadAsStringAsync();
            var configuration = JsonNode.Parse(configurationResponseString);

            //Get keys
            var keysUrl = configuration["jwks_uri"]?.ToString();
            var keysRequest = new HttpRequestMessage(HttpMethod.Get, keysUrl);
            keysRequest.Headers.Add("Accept", "application/json");
            var keysResponse = await client.SendAsync(keysRequest);
            var keysResponseString = await keysResponse.Content.ReadAsStringAsync();
            var keysParse = JsonNode.Parse(keysResponseString);
            var keys = keysParse["keys"]?.AsArray();

            var keyJson = "";
            foreach(var key in keys)
            {
                if(key["kid"]?.ToString() == headerKid)
                {
                    keyJson = JsonSerializer.Serialize(key, new JsonSerializerOptions { WriteIndented = true });
                    break;
                }
            }

            return keyJson;
        }
    }
}
