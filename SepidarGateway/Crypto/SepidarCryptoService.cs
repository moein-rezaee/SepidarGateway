using System.Security.Cryptography;
using System.Text;
using System.Xml;
using SepidarGateway.Configuration;

namespace SepidarGateway.Crypto;

public sealed class SepidarCryptoService : ISepidarCrypto
{
    public (string CipherText, string IvBase64) EncryptRegisterPayload(string serialSeed, string payload)
    {
        return EncryptRegisterPayload(serialSeed, payload, 16);
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
        try
        {
            return DecryptRegisterPayloadInternal(serialSeed, cipherTextBase64, ivBase64, 16);
        }
        catch (CryptographicException) when (!string.IsNullOrEmpty(serialSeed))
        {
            // Older devices may still rely on AES-256; retry with a 32-byte key before failing.
            return DecryptRegisterPayloadInternal(serialSeed, cipherTextBase64, ivBase64, 32);
        }
    }

    private static string DecryptRegisterPayloadInternal(string serialSeed, string cipherTextBase64, string ivBase64, int keyBytes)
    {
        using var AesCipher = Aes.Create();
        AesCipher.Mode = CipherMode.CBC;
        AesCipher.Padding = PaddingMode.PKCS7;
        AesCipher.Key = DeriveKey(serialSeed, keyBytes);
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
        // طبق مستند رسمی، مقدار رمز شده باید همان رشته ارسال شده در هدر ArbitraryCode باشد.
        // بنابراین همیشه رشته را با UTF8 به بایت تبدیل می‌کنیم تا پس از رمزگشایی دقیقاً همان مقدار بازسازی شود.
        var ArbitraryBytes = Encoding.UTF8.GetBytes(arbitraryCode ?? string.Empty);
        var EncryptedBytes = RsaProvider.Encrypt(ArbitraryBytes, RSAEncryptionPadding.Pkcs1);
        return Convert.ToBase64String(EncryptedBytes);
    }

    private static byte[] DeriveKey(string serialSeed, int keyBytes)
    {
        var seedBytes = Encoding.UTF8.GetBytes(serialSeed ?? string.Empty);

        if (seedBytes.Length == 0)
        {
            return new byte[keyBytes];
        }

        if (seedBytes.Length == keyBytes)
        {
            return seedBytes;
        }

        var buffer = new byte[keyBytes];
        var position = 0;

        while (position < keyBytes)
        {
            var bytesToCopy = Math.Min(seedBytes.Length, keyBytes - position);
            Array.Copy(seedBytes, 0, buffer, position, bytesToCopy);
            position += bytesToCopy;
        }

        return buffer;
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
