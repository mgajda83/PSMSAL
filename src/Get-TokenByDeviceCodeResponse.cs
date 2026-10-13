using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net.Http;

namespace PSMSAL
{
    /// <summary>
    /// <para type="synopsis">Get OAuth access token using device code - Response.</para>
    /// </summary>

    /// <example>
    /// <code>
    /// <para>Get token by user credential.</para>
    ///
    /// $TenantId = "12345678-1234-1234-1234-1234567890ab"
	///	$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
	///	$DeviceCode = "Device Code returned by Get-TokenByDeviceCodeRequest"
    ///
	///	#Token
	///	$AccessToken = Get-TokenByDeviceCodeResponse -TenantId $TenantId -ApplicationId $ApplicationId -DeviceCode $DeviceCode
	///	$AccessToken
    /// </code>
    /// </example>

    [Cmdlet(VerbsCommon.Get,"TokenByDeviceCodeResponse")]
    public class GetTokenByDeviceCodeResponseCmdletCommand : PSCmdlet
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
        /// <para type="description">Device code from request.</para>
        /// </summary>
        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true)]
        public string DeviceCode { get; set; }

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
            WriteVerbose("Begin Get-TokenByDeviceCodeResponse!");
            //WriteVerbose(this.ParameterSetName);
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
        var tokenUrl = $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token";

            var parameters = new Dictionary<string, string>
            {
                { "address", tokenUrl },
                { "client_id", ClientId },
                { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
                { "device_code", DeviceCode }
            };
            WriteVerbose("Sending request to token endpoint: " + tokenUrl);
            WriteVerbose("client_id: " + parameters["client_id"]);
            WriteVerbose("grant_type: " + parameters["grant_type"]);

            var httpClient = new HttpClient();
            var processRecordInBackground = Task
                .Run(async () => await this.HttpClientRequest(httpClient, tokenUrl, parameters));

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

        public async Task<string> HttpClientRequest(HttpClient client, string url, Dictionary<string, string> parameters)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Add("Accept", "application/json");
            request.Content = new FormUrlEncodedContent(parameters);
            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();

            return responseString;
        }
    }
}
