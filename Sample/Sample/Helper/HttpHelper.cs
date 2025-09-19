using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;

using Newtonsoft.Json;

using Sample.DTO;

namespace Sample.Helper
{
    static class HttpHelper
    {
        public static T GetResponseObject<T>(string jsonContent)
            where T : class
        {
            return JsonConvert.DeserializeObject(jsonContent, typeof(T)) as T;
        }

        public static void AddRange(this HttpRequestHeaders headers, Dictionary<string, string> pairs)
        {
            foreach (var item in pairs)
            {
                headers.Add(item.Key, item.Value);
            }
        }

        public static TResponse Post<TRequest, TResponse>(this HttpClient client, string url, TRequest data)
            where TResponse : class
        {
            var response = client.PostAsync(url, new JsonContent(data)).Result;
            var jsonContent = response.Content.ReadAsStringAsync().Result;

            if (!response.IsSuccessStatusCode)
            {
                var error = GetResponseObject<ErrorResponse>(jsonContent);
                throw new Exception(error?.Message ?? string.Empty);
            }

            var registerResponse = HttpHelper.GetResponseObject<TResponse>(jsonContent);
            return registerResponse;
        }

        public static TResponse Get<TResponse>(this HttpClient client, string url)
            where TResponse : class
        {
            var response = client.GetAsync(url).Result;
            var jsonContent = response.Content.ReadAsStringAsync().Result;

            if (!response.IsSuccessStatusCode)
            {
                var error = GetResponseObject<ErrorResponse>(jsonContent);
                throw new Exception(error?.Message ?? string.Empty);
            }

            var registerResponse = HttpHelper.GetResponseObject<TResponse>(jsonContent);
            return registerResponse;
        }
    }
}
