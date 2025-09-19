using SepidarGateway.Configuration;

namespace SepidarGateway.Crypto;

public interface ISepidarCrypto
{
    (string CipherText, string IvBase64) EncryptRegisterPayload(string serialSeed, string payload);

    string DecryptRegisterPayload(string serialSeed, string cipherTextBase64, string ivBase64);

    string EncryptArbitraryCode(string arbitraryCode, TenantCryptoOptions cryptoOptions);
}
