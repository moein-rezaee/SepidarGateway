using System.Security.Cryptography;
using System.Text;
using System.Xml;
using SepidarGateway.Configuration;

namespace SepidarGateway.Crypto;

public sealed class SepidarCryptoService : ISepidarCrypto
{
    public (string CipherText, string IvBase64) EncryptRegisterPayload(string serialSeed, string payload)
    {
        return EncryptRegisterPayload(serialSeed, payload, 32);
    }

    public (string CipherText, string IvBase64) EncryptRegisterPayload(string serialSeed, string payload, int keyBytes)
    {
        using var AesCipher = Aes.Create();
        AesCipher.Mode = CipherMode.CBC;
        AesCipher.Padding = PaddingMode.PKCS7;
        AesCipher.Key = DeriveKey(serialSeed, keyBytes);
        AesCipher.GenerateIV();

        using var AesEncryptor = AesCipher.CreateEncryptor();
        var PlainBytes = Encoding.UTF8.GetBytes(payload);
        var CipherBytes = AesEncryptor.TransformFinalBlock(PlainBytes, 0, PlainBytes.Length);
        return (Convert.ToBase64String(CipherBytes), Convert.ToBase64String(AesCipher.IV));
    }

    public string DecryptRegisterPayload(string serialSeed, string cipherTextBase64, string ivBase64)
    {
        using var AesCipher = Aes.Create();
        AesCipher.Mode = CipherMode.CBC;
        AesCipher.Padding = PaddingMode.PKCS7;
        // Must mirror EncryptRegisterPayload key derivation (default 32 bytes)
        AesCipher.Key = DeriveKey(serialSeed, 32);
        AesCipher.IV = Convert.FromBase64String(ivBase64);

        using var AesDecryptor = AesCipher.CreateDecryptor();
        var CipherBytes = Convert.FromBase64String(cipherTextBase64);
        var PlainBytes = AesDecryptor.TransformFinalBlock(CipherBytes, 0, CipherBytes.Length);
        return Encoding.UTF8.GetString(PlainBytes);
    }

    public string EncryptArbitraryCode(string arbitraryCode, TenantCryptoOptions cryptoOptions)
    {
        using var RsaProvider = RSA.Create();
        ImportRsaParameters(RsaProvider, cryptoOptions);
        // طبق داکیومنت/نمونه Python: مقدار RSA باید روی بایت‌های UUID (16 بایت) اعمال شود،
        // نه روی متن رشته. در صورت امکان رشته را به Guid تبدیل و از بایت‌های آن استفاده می‌کنیم.
        byte[] ArbitraryBytes;
        if (Guid.TryParse(arbitraryCode, out var guidValue))
        {
            ArbitraryBytes = guidValue.ToByteArray();
        }
        else
        {
            ArbitraryBytes = Encoding.UTF8.GetBytes(arbitraryCode ?? string.Empty);
        }
        var EncryptedBytes = RsaProvider.Encrypt(ArbitraryBytes, RSAEncryptionPadding.Pkcs1);
        return Convert.ToBase64String(EncryptedBytes);
    }

    private static byte[] DeriveKey(string serialSeed, int keyBytes)
    {
        // Build keyBytes-length key: (serial + serial) then zero-pad/truncate.
        var seed = (serialSeed ?? string.Empty) + (serialSeed ?? string.Empty);
        var bytes = Encoding.UTF8.GetBytes(seed);
        if (bytes.Length == keyBytes)
        {
            return bytes;
        }
        if (bytes.Length > keyBytes)
        {
            return bytes.Take(keyBytes).ToArray();
        }
        var buf = new byte[keyBytes];
        Array.Copy(bytes, buf, bytes.Length);
        return buf;
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
        var XmlDocument = new XmlDocument();
        XmlDocument.LoadXml(xml);
        if (XmlDocument.DocumentElement?.Name != "RSAKeyValue")
        {
            throw new InvalidOperationException("Invalid RSA key XML.");
        }

        var RsaModulus = Convert.FromBase64String(XmlDocument.DocumentElement.SelectSingleNode("Modulus")?.InnerText ?? throw new InvalidOperationException("Missing modulus"));
        var RsaExponent = Convert.FromBase64String(XmlDocument.DocumentElement.SelectSingleNode("Exponent")?.InnerText ?? throw new InvalidOperationException("Missing exponent"));

        rsa.ImportParameters(new RSAParameters
        {
            Modulus = RsaModulus,
            Exponent = RsaExponent
        });
    }
}
