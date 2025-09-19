using System.Collections.Generic;

using Flurl;

namespace Sample.Base
{
    class Configuration : IBaseService
    {
        private readonly string baseUrl;
        private readonly string apiVersion;

        public Configuration(string baseUrl, string apiVersion)
        {
            this.baseUrl = baseUrl;
            this.apiVersion = apiVersion;
        }

        public string GetAbsoluteUrl(string endpoint)
        {
            return Url.Combine(baseUrl, endpoint);
        }

        public Dictionary<string, string> CreateHeaders()
        {
            return new Dictionary<string, string>
            {
                { "GenerationVersion", apiVersion }
            };
        }
    }
}
