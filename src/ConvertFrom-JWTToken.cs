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
        public SwitchParameter AsJSON { get; set; }

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Begin!");
            WriteVerbose(this.ParameterSetName);
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
            var headerData = header.Replace('-', '+').Replace('_', '/');
            while (headerData.Length % 4 != 0)
            {
                headerData += '=';
            }
            var decodedHeaderJSON = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(headerData));
            var decodedHeader = JsonNode.Parse(decodedHeaderJSON);
            var headerObject = new PSObject();
            foreach (var property in decodedHeader.AsObject())
            {
                headerObject.Properties.Add(new PSNoteProperty(property.Key, property.Value.ToString()));
            }
            DecodedToken.Properties.Add(new PSNoteProperty("Header", headerObject));

            //Decode Payload
            var payloadData = payload.Replace('-', '+').Replace('_', '/');
            while (payloadData.Length % 4 != 0)
            {
                payloadData += '=';
            }
            var decodedPayloadJSON = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payloadData));
            var decodedPayload = JsonNode.Parse(decodedPayloadJSON);
            var payloadObject = new PSObject();
            foreach (var property in decodedPayload.AsObject())
            {
                payloadObject.Properties.Add(new PSNoteProperty(property.Key, property.Value.ToString()));
            }
            DecodedToken.Properties.Add(new PSNoteProperty("Payload", payloadObject));

            //Get expiration time
            var unixTime = new DateTime(1970, 1, 1);
            var utcTime = unixTime.AddSeconds(decodedPayload["exp"].GetValue<long>());
            var expiryDateTime = utcTime.AddMinutes(TimeZone.CurrentTimeZone.GetUtcOffset(DateTime.Now).TotalMinutes);
            DecodedToken.Properties.Add(new PSNoteProperty("ExpirationTime", expiryDateTime));

            if(ValidateSignature)
            {
                var httpClient = new HttpClient();
                var processRecordInBackground = Task
                    .Run(async () => await this.RequestValidateSignature(httpClient, decodedPayload["iss"].ToString(), decodedHeader["kid"].ToString()));

                // await the finalization of the BG task
                var result = processRecordInBackground.GetAwaiter().GetResult();

                // if found key
                var keyInfo = new PSObject();
                if(!string.IsNullOrEmpty(result))
                {
                    var keyParse = JsonNode.Parse(result);
                    foreach (var property in keyParse.AsObject())
                    {
                        keyInfo.Properties.Add(new PSNoteProperty(property.Key, property.Value.ToString()));
                    }

                    var x5c = JsonNode.Parse(keyParse["x5c"]?.ToString())[0].ToString();
                    X509Certificate2 X509Certificate = new X509Certificate2(Convert.FromBase64String(x5c));
                    keyInfo.Properties.Add(new PSNoteProperty("X509Certificate", X509Certificate));
                    DecodedToken.Properties.Add(new PSNoteProperty("KeyInfo", keyInfo));

                    //Validate Signature
                    var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
                    var rsaParameters = new System.Security.Cryptography.RSAParameters();

                    var kayNData = keyParse["n"]?.ToString().Replace('-', '+').Replace('_', '/');
                    while (kayNData.Length % 4 != 0)
                    {
                        kayNData += '=';
                    }
                    rsaParameters.Modulus = Convert.FromBase64String(kayNData);

                    var kayEData = keyParse["e"]?.ToString().Replace('-', '+').Replace('_', '/');
                    while (kayEData.Length % 4 != 0)
                    {
                        kayEData += '=';
                    }
                    rsaParameters.Exponent = Convert.FromBase64String(kayEData);

                    rsa.ImportParameters(rsaParameters);

                    var signatureDeformatter = new System.Security.Cryptography.RSAPKCS1SignatureDeformatter(rsa);
                    signatureDeformatter.SetHashAlgorithm("SHA256");

                    var sha256 = System.Security.Cryptography.SHA256.Create();
                    var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(header + "." + payload));

                    var signatureData = signature.Replace('-', '+').Replace('_', '/');
                    while (signatureData.Length % 4 != 0)
                    {
                        signatureData += '=';
                    }
                    var signatureBytes = Convert.FromBase64String(signatureData);

                    if(signatureDeformatter.VerifySignature(hash,signatureBytes))
                    {
                        DecodedToken.Properties.Add(new PSNoteProperty("SignatureStatus", "Signature Verified"));
                    }
                    else
                    {
                        if(decodedPayload["aud"]?.ToString() == "https://graph.microsoft.com")
                        {
                            DecodedToken.Properties.Add(new PSNoteProperty("SignatureStatus", "Cant validate MSGraph token signature"));
                        }
                        else
                        {
                            DecodedToken.Properties.Add(new PSNoteProperty("SignatureStatus", "Invalid Signature"));
                        }
                    }
                }
            }

            if(AsJSON)
            {
                var tokenJson = JsonSerializer.Serialize(DecodedToken, new JsonSerializerOptions { WriteIndented = true });
                WriteObject(tokenJson);
            }
            else
            {
                WriteObject(DecodedToken);
            }
        }

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            WriteVerbose("End!");
        }

       public async Task<string> RequestValidateSignature(HttpClient client, string payloadIssuer, string headerKid)
        {
            //Get tenant configurations
            var configurationUrl = $"{payloadIssuer}.well-known/openid-configuration";

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
