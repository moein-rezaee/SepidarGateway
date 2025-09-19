using System.Security.Cryptography;
using System.Text;
using System.Xml;
using SepidarGateway.Configuration;

namespace SepidarGateway.Crypto;

public sealed class SepidarCryptoService : ISepidarCrypto
{
    public (string CipherText, string IvBase64) EncryptRegisterPayload(string serialSeed, string payload)
    {
        using var aes_cipher = Aes.Create();
        aes_cipher.Mode = CipherMode.CBC;
        aes_cipher.Padding = PaddingMode.PKCS7;
        aes_cipher.Key = DeriveKey(serialSeed);
        aes_cipher.GenerateIV();

        using var aes_encryptor = aes_cipher.CreateEncryptor();
        var plain_bytes = Encoding.UTF8.GetBytes(payload);
        var cipher_bytes = aes_encryptor.TransformFinalBlock(plain_bytes, 0, plain_bytes.Length);
        return (Convert.ToBase64String(cipher_bytes), Convert.ToBase64String(aes_cipher.IV));
    }

    public string DecryptRegisterPayload(string serialSeed, string cipherTextBase64, string ivBase64)
    {
        using var aes_cipher = Aes.Create();
        aes_cipher.Mode = CipherMode.CBC;
        aes_cipher.Padding = PaddingMode.PKCS7;
        aes_cipher.Key = DeriveKey(serialSeed);
        aes_cipher.IV = Convert.FromBase64String(ivBase64);

        using var aes_decryptor = aes_cipher.CreateDecryptor();
        var cipher_bytes = Convert.FromBase64String(cipherTextBase64);
        var plain_bytes = aes_decryptor.TransformFinalBlock(cipher_bytes, 0, cipher_bytes.Length);
        return Encoding.UTF8.GetString(plain_bytes);
    }

    public string EncryptArbitraryCode(string arbitraryCode, TenantCryptoOptions cryptoOptions)
    {
        using var rsa_provider = RSA.Create();
        ImportRsaParameters(rsa_provider, cryptoOptions);
        var arbitrary_bytes = Encoding.UTF8.GetBytes(arbitraryCode);
        var encrypted_bytes = rsa_provider.Encrypt(arbitrary_bytes, RSAEncryptionPadding.Pkcs1);
        return Convert.ToBase64String(encrypted_bytes);
    }

    private static byte[] DeriveKey(string serialSeed)
    {
        var serial_seed = serialSeed + serialSeed;
        var seed_bytes = Encoding.UTF8.GetBytes(serial_seed);
        if (seed_bytes.Length == 32)
        {
            return seed_bytes;
        }

        if (seed_bytes.Length > 32)
        {
            return seed_bytes.Take(32).ToArray();
        }

        var seed_buffer = new byte[32];
        Array.Copy(seed_bytes, seed_buffer, seed_bytes.Length);
        return seed_buffer;
    }

    private static void ImportRsaParameters(RSA rsa, TenantCryptoOptions cryptoOptions)
    {
        if (!string.IsNullOrWhiteSpace(cryptoOptions.RsaPublicKeyXml))
        {
            rsa.FromXmlString(cryptoOptions.RsaPublicKeyXml);
            return;
        }

        if (!string.IsNullOrWhiteSpace(cryptoOptions.RsaModulusBase64) &&
            !string.IsNullOrWhiteSpace(cryptoOptions.RsaExponentBase64))
        {
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = Convert.FromBase64String(cryptoOptions.RsaModulusBase64),
                Exponent = Convert.FromBase64String(cryptoOptions.RsaExponentBase64)
            });
            return;
        }

        throw new InvalidOperationException("No RSA public key configured for tenant.");
    }
}

internal static class RsaExtensions
{
    public static void FromXmlString(this RSA rsa, string xml)
    {
        var xml_document = new XmlDocument();
        xml_document.LoadXml(xml);
        if (xml_document.DocumentElement?.Name != "RSAKeyValue")
        {
            throw new InvalidOperationException("Invalid RSA key XML.");
        }

        var rsa_modulus = Convert.FromBase64String(xml_document.DocumentElement.SelectSingleNode("Modulus")?.InnerText ?? throw new InvalidOperationException("Missing modulus"));
        var rsa_exponent = Convert.FromBase64String(xml_document.DocumentElement.SelectSingleNode("Exponent")?.InnerText ?? throw new InvalidOperationException("Missing exponent"));

        rsa.ImportParameters(new RSAParameters
        {
            Modulus = rsa_modulus,
            Exponent = rsa_exponent
        });
    }
}
