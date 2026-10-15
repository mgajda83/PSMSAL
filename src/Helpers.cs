using System;
using System.Reflection;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net.Http;

namespace PSMSAL
{
    public class Helpers
    {
        /// <summary>
        /// <para type="description">Decode part of JWT token to byte array.</para>
        /// </summary>
        /// <param name="partToken"></param>
        /// <returns></returns>
        public byte[] DecodePartTokenToBytes(string partToken)
        {
            var data = partToken.Replace('-', '+').Replace('_', '/');
            while (data.Length % 4 != 0)
            {
                data += '=';
            }
            var decodedBytes = Convert.FromBase64String(data);

            return decodedBytes;
        }

        /// <summary>
        /// <para type="description">Decode part of JWT token to JSON string.</para>
        /// </summary>
        /// <param name="partToken"></param>
        /// <returns></returns>
        public string DecodePartToken(string partToken)
        {
            var decodedJSON = System.Text.Encoding.UTF8.GetString(this.DecodePartTokenToBytes(partToken));

            return decodedJSON;
        }

        /// <summary>
        /// <para type="description">Get expiration time from Unix timestamp.</para>
        /// </summary>
        /// <param name="exp"></param>
        /// <returns></returns>
        public DateTime GetExpirationTime(long exp)
        {
            var unixTime = new DateTime(1970, 1, 1);
            var utcTime = unixTime.AddSeconds(exp);
            var expiryDateTime = utcTime.AddMinutes(TimeZoneInfo.Local.GetUtcOffset(DateTime.Now).TotalMinutes);
            //var expiryDateTime = utcTime.AddMinutes(TimeZone.CurrentTimeZone.GetUtcOffset(DateTime.Now).TotalMinutes);

            return expiryDateTime;
        }

    }

}