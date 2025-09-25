using SepidarGateway.Contracts;

namespace SepidarGateway.Services;

public interface ILoginCache
{
    bool TryGet(string userName, string password, out DeviceLoginResponseDto? response);

    void Set(string userName, string password, DeviceLoginResponseDto response);

    void Remove(string userName, string password);
}
