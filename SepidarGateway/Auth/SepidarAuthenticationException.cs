using System.Net;

namespace SepidarGateway.Auth;

public sealed class SepidarAuthenticationException : Exception
{
    public SepidarAuthenticationException(HttpStatusCode statusCode, string message, string? responseBody = null)
        : base(string.IsNullOrWhiteSpace(message)
            ? $"Sepidar authentication failed with status code {(int)statusCode}."
            : message)
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
    }

    public HttpStatusCode StatusCode { get; }

    public string? ResponseBody { get; }
}
