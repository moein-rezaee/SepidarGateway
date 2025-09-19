using System.Collections.Generic;

namespace Sample.Base
{
    internal interface IBaseService
    {
        Dictionary<string, string> CreateHeaders();
        string GetAbsoluteUrl(string endpoint);
    }
}