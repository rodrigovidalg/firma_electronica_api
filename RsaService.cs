using System.Security.Cryptography;

namespace firma_electronica_api;

public class RsaService
{
    private readonly RSA _rsa;

    public RsaService(IConfiguration config)
    {
        _rsa = RSA.Create();

        var private_key = config["Rsa:PrivateKey"];
        var public_key  = config["Rsa:PublicKey"];

        if (!string.IsNullOrEmpty(private_key) && !string.IsNullOrEmpty(public_key))
        {
            _rsa.ImportRSAPrivateKey(Convert.FromBase64String(private_key), out _);
        }
        else
        {
            // Si no hay claves configuradas, genera un par nuevo
            // Esto solo pasa en desarrollo — en Railway siempre deben estar configuradas
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
            var firma_bytes = Convert.FromBase64String(firma_base64);
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
}