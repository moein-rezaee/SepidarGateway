using System;
using Microsoft.Extensions.Caching.Memory;

namespace SepidarGateway.Services;

public interface IRegisterPayloadCache
{
    void Store(RegisterPayloadCacheEntry entry, TimeSpan lifetime);

    bool TryGet(out RegisterPayloadCacheEntry? entry);

    void Clear();
}

public sealed record RegisterPayloadCacheEntry(
    string DeviceSerial,
    string Cypher,
    string IV,
    string? DeviceTitle);

public sealed class InMemoryRegisterPayloadCache : IRegisterPayloadCache
{
    private const string CacheKey = "SepidarGateway:RegisterPayload";
    private readonly IMemoryCache _memoryCache;

    public InMemoryRegisterPayloadCache(IMemoryCache memoryCache)
    {
        _memoryCache = memoryCache;
    }

    public void Store(RegisterPayloadCacheEntry entry, TimeSpan lifetime)
    {
        if (entry is null)
        {
            throw new ArgumentNullException(nameof(entry));
        }

        var options = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = lifetime
        };

        _memoryCache.Set(CacheKey, entry, options);
    }

    public bool TryGet(out RegisterPayloadCacheEntry? entry)
    {
        if (_memoryCache.TryGetValue(CacheKey, out RegisterPayloadCacheEntry? cached) && cached is not null)
        {
            entry = cached;
            return true;
        }

        entry = null;
        return false;
    }

    public void Clear()
    {
        _memoryCache.Remove(CacheKey);
    }
}
