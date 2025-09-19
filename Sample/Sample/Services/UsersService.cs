using System.Collections.Generic;
using System.Net.Http;

using Sample.Base;
using Sample.DTO;
using Sample.Helper;

namespace Sample.Services
{
    class UsersService : IBaseService
    {
        private readonly DevicesService device;
        private string token;

        public string UserTile { get; private set; }

        public UsersService(DevicesService device)
        {
            this.device = device;
        }

        public void Login(string username, string password)
        {
            var url = GetAbsoluteUrl("/api/users/login");
            var data = new LoginRequest
            {
                UserName = username,
                PasswordHash = CryptoHelper.CreateMD5(password),
            };

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.AddRange(device.CreateHeaders());
                var loginResponse = client.Post<LoginRequest, LoginResponse>(url, data);
                token = loginResponse.Token;
                UserTile = loginResponse.Title;
            }
        }

        public void Logout()
        {
            token = null;
            UserTile = null;
        }

        public Dictionary<string, string> CreateHeaders()
        {
            var headers = device.CreateHeaders();

            if (!string.IsNullOrEmpty(token))
            {
                headers["Authorization"] = $"Bearer {token}";
            }

            return headers;
        }

        public string GetAbsoluteUrl(string endpoint)
        {
            return device.GetAbsoluteUrl(endpoint);
        }
    }
}
