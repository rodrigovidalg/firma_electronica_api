using System.Security.Cryptography;

namespace firma_electronica_api;

public class RsaService
{
    private readonly RSA _rsa;

    public RsaService(IConfiguration config)
    {
        var private_key = config["Rsa:PrivateKey"];

        if (string.IsNullOrEmpty(private_key))
            throw new InvalidOperationException(
                "❌ Rsa:PrivateKey no está configurada. Agrega la variable de entorno Rsa__PrivateKey en Railway.");

        try
        {
            _rsa = RSA.Create();
            _rsa.ImportRSAPrivateKey(Convert.FromBase64String(private_key), out _);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"❌ No se pudo importar la clave privada RSA: {ex.Message}");
        }
    }

    public string FirmarBytes(byte[] contenido)
    {
        var firma = _rsa.SignData(contenido, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(firma);
    }

    public bool VerificarFirma(byte[] contenido, string firma_base64)
    {
        try
        {
            var firma_bytes = Convert.FromBase64String(firma_base64.Trim());
            return _rsa.VerifyData(contenido, firma_bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    public string ObtenerClavePublica()
    {
        return Convert.ToBase64String(_rsa.ExportRSAPublicKey());
    }

    // Calcula el SHA-256 del PDF — es la llave para buscar en BD
    public static string ComputarHashPdf(byte[] pdf_bytes)
    {
        var hash = SHA256.HashData(pdf_bytes);
        return Convert.ToHexString(hash).ToLower();
    }
}