using Microsoft.AspNetCore.Http;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Coffee.WebUI.Models
{
    public class Utils
    {
        public static string HmacSHA512(string key, string inputData)
        {
            var hash = new StringBuilder();
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] inputBytes = Encoding.UTF8.GetBytes(inputData);
            using (var hmac = new HMACSHA512(keyBytes))
            {
                byte[] hashValue = hmac.ComputeHash(inputBytes);
                foreach (var theByte in hashValue)
                {
                    hash.Append(theByte.ToString("x2"));
                }
            }

            return hash.ToString();
        }

        public static string GetIpAddress(HttpContext httpContext)
        {
            string ipAddress;
            try
            {
                if (httpContext?.Connection?.RemoteIpAddress != null)
                {
                    ipAddress = httpContext.Connection.RemoteIpAddress.ToString();
                }
                else
                {
                    ipAddress = "Unknown";
                }
            }
            catch (Exception ex)
            {
                ipAddress = "Invalid IP: " + ex.Message;
            }

            return ipAddress;
        }
    }
}
