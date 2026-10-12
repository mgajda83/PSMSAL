using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Text.Json.Nodes;
using System.Net.Http;

namespace PSMSAL
{
    /// <summary>
    /// <para type="synopsis">Get OAuth access token using device code - Request.</para>
    /// </summary>

    /// <example>
    /// <code>
    /// <para>Get token by user credential.</para>
    ///
    /// $TenantId = "12345678-1234-1234-1234-1234567890ab"
	///	$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
	///	$Scope = "Mail.Send.Shared Mail.ReadWrite.Shared"
    ///
	///	#Token
	///	$Request = Get-TokenByDeviceCodeRequest -TenantId $TenantId -ApplicationId $ApplicationId -Scope $Scope
	///	$Request
    /// </code>
    /// </example>

    [Cmdlet(VerbsCommon.Get,"TokenByDeviceCodeRequest")]
    public class GetTokenByDeviceCodeRequestCmdletCommand : PSCmdlet
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

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Begin!");
            WriteVerbose(this.ParameterSetName);
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
            var httpClient = new HttpClient();
            var processRecordInBackground = Task
                .Run(async () => await this.RequestToken(httpClient));

            // await the finalization of the BG task
            var device_code = processRecordInBackground.GetAwaiter().GetResult();
            WriteObject(device_code);
        }

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            WriteVerbose("End!");
        }

        public async Task<string> RequestToken(HttpClient client)
        {
            var tokenUrl = $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/devicecode";

            var parameters = new Dictionary<string, string>
            {
                { "address", tokenUrl },
                { "client_id", ClientId },
                { "scope", string.Join(" ", Scopes) }
            };

            var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl);
            request.Headers.Add("Accept", "application/json");
            request.Content = new FormUrlEncodedContent(parameters);
            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();
            var responseStringParse = JsonNode.Parse(responseString);
            var device_code = responseStringParse["device_code"]?.ToString();
            var message = responseStringParse["message"]?.ToString();

            Console.WriteLine(message);

            return device_code;
        }
    }
}
