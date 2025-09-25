using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using SepidarGateway.Contracts;

namespace SepidarGateway.Services;

public sealed class InMemoryLoginCache : ILoginCache
{
    private readonly ConcurrentDictionary<string, CachedLoginEntry> _entries = new();

    public bool TryGet(string userName, string password, out DeviceLoginResponseDto? response)
    {
        response = null;
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            return false;
        }

        var key = CreateKey(userName, password);
        if (!_entries.TryGetValue(key, out var entry))
        {
            return false;
        }

        if (entry.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _entries.TryRemove(key, out _);
            return false;
        }

        response = Clone(entry.Response);
        return true;
    }

    public void Set(string userName, string password, DeviceLoginResponseDto response)
    {
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        var key = CreateKey(userName, password);
        var entry = new CachedLoginEntry(Clone(response), response.ExpiresAt);
        _entries[key] = entry;
    }

    public void Remove(string userName, string password)
    {
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        var key = CreateKey(userName, password);
        _entries.TryRemove(key, out _);
    }

    private static string CreateKey(string userName, string password)
    {
        var normalizedUser = userName.Trim();
        var normalizedPassword = password.Trim();
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes($"{normalizedUser}\u001f{normalizedPassword}");
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash);
    }

    private static DeviceLoginResponseDto Clone(DeviceLoginResponseDto source)
    {
        return new DeviceLoginResponseDto
        {
            Token = source.Token,
            ExpiresIn = source.ExpiresIn,
            ExpiresAt = source.ExpiresAt,
            UserId = source.UserId,
            UserName = source.UserName,
            Title = source.Title,
            CanEditCustomer = source.CanEditCustomer,
            CanRegisterCustomer = source.CanRegisterCustomer,
            CanRegisterOrder = source.CanRegisterOrder,
            CanRegisterReturnOrder = source.CanRegisterReturnOrder,
            CanRegisterInvoice = source.CanRegisterInvoice,
            CanRegisterReturnInvoice = source.CanRegisterReturnInvoice,
            CanPrintInvoice = source.CanPrintInvoice,
            CanPrintReturnInvoice = source.CanPrintReturnInvoice,
            CanPrintInvoiceBeforeSend = source.CanPrintInvoiceBeforeSend,
            CanPrintReturnInvoiceBeforeSend = source.CanPrintReturnInvoiceBeforeSend,
            CanRevokeInvoice = source.CanRevokeInvoice
        };
    }

    private sealed record CachedLoginEntry(DeviceLoginResponseDto Response, DateTimeOffset ExpiresAt);
}
