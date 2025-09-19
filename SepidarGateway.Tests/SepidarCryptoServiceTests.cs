using System.Security.Cryptography;
using System.Text;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using Xunit;

namespace SepidarGateway.Tests;

public class SepidarCryptoServiceTests
{
    [Fact]
    public void EncryptAndDecryptRegisterPayload_RoundTripsOriginalText()
    {
        var cryptoService = new SepidarCryptoService();
        const string serial = "10006c18";
        const string payload = "{\"DeviceSerial\":\"10006c18\"}";

        var encrypted = cryptoService.EncryptRegisterPayload(serial, payload);
        Assert.False(string.IsNullOrWhiteSpace(encrypted.CipherText));
        Assert.False(string.IsNullOrWhiteSpace(encrypted.IvBase64));

        var decrypted = cryptoService.DecryptRegisterPayload(serial, encrypted.CipherText, encrypted.IvBase64);
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void EncryptArbitraryCode_RespectsProvidedRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var rsaParameters = rsa.ExportParameters(true);

        var cryptoOptions = new TenantCryptoOptions
        {
            RsaModulusBase64 = Convert.ToBase64String(rsaParameters.Modulus!),
            RsaExponentBase64 = Convert.ToBase64String(rsaParameters.Exponent!)
        };

        var cryptoService = new SepidarCryptoService();
        var arbitraryCode = Guid.NewGuid().ToString();

        var encrypted = cryptoService.EncryptArbitraryCode(arbitraryCode, cryptoOptions);
        Assert.False(string.IsNullOrWhiteSpace(encrypted));

        using var rsaForDecrypt = RSA.Create();
        rsaForDecrypt.ImportParameters(rsaParameters);
        var decryptedBytes = rsaForDecrypt.Decrypt(Convert.FromBase64String(encrypted), RSAEncryptionPadding.Pkcs1);
        var decrypted = Encoding.UTF8.GetString(decryptedBytes);

        Assert.Equal(arbitraryCode, decrypted);
    }
}
