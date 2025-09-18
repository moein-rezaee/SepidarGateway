using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using Xunit;

namespace SepidarGateway.Tests.Crypto;

public class SepidarCryptoServiceTests
{
    private readonly SepidarCryptoService _crypto = new();

    [Fact]
    public void EncryptAndDecryptRegisterPayload_RoundTrips()
    {
        var payload = "{\"hello\":\"world\"}";
        var serial = "SER123";

        var encrypted = _crypto.EncryptRegisterPayload(serial, payload);
        var decrypted = _crypto.DecryptRegisterPayload(serial, encrypted.CipherText, encrypted.IvBase64);

        decrypted.Should().Be(payload);
    }

    [Fact]
    public void EncryptArbitraryCode_ProducesDecryptableCipher()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        var options = new TenantCryptoOptions
        {
            RsaModulusBase64 = Convert.ToBase64String(parameters.Modulus!),
            RsaExponentBase64 = Convert.ToBase64String(parameters.Exponent!)
        };

        var arbitrary = Guid.NewGuid().ToString();
        var cipher = _crypto.EncryptArbitraryCode(arbitrary, options);

        var decrypted = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(cipher), RSAEncryptionPadding.Pkcs1));
        decrypted.Should().Be(arbitrary);
    }
}
