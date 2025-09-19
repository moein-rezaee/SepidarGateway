using System;
using System.Collections.Generic;
using System.Net.Http;

using Sample.Base;
using Sample.DTO;
using Sample.Helper;

namespace Sample.Services
{
    class DevicesService : IBaseService
    {
        private readonly Configuration config;
        private readonly string registrationCode;
        private readonly string integrationId;
        private string publicKey;

        public string DeviceName { get; private set; }

        public DevicesService(Configuration config, string code)
        {
            this.config = config;
            registrationCode = code;
            integrationId = code.Substring(0, 4);
        }

        public void Register()
        {
            var url = GetAbsoluteUrl("/api/Devices/Register/");
            var encryptionKey = registrationCode + registrationCode;
            var encryptedData = CryptoHelper.AesEncrypt(encryptionKey, integrationId);

            var data = new RegisterDeviceRequest
            {
                Cypher = encryptedData.Cipher,
                IV = encryptedData.IV,
                IntegrationID = integrationId,
            };

            using (var client = new HttpClient())
            {
                var registerResponse = client.Post<RegisterDeviceRequest, RegisterDeviceResponse>(url, data);
                publicKey = CryptoHelper.AesDecrypt(encryptionKey, registerResponse.Cypher, registerResponse.IV);
                DeviceName = registerResponse.DeviceTitle;
            }
        }

        public Dictionary<string, string> CreateHeaders()
        {
            var headers = config.CreateHeaders();

            headers["IntegrationID"] = integrationId;

            var guid = Guid.NewGuid();
            headers["ArbitraryCode"] = guid.ToString();
            headers["EncArbitraryCode"] = CryptoHelper.RsaEncrypt(publicKey, guid.ToByteArray());

            return headers;
        }

        public string GetAbsoluteUrl(string endpoint)
        {
            return config.GetAbsoluteUrl(endpoint);
        }
    }
}
