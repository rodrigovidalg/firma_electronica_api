using System.Security.Cryptography;
using iText.Bouncycastle.Crypto;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Pkcs;

namespace firma_electronica_api;

public class RsaService
{
    private readonly byte[]  _pfx_bytes;
    private readonly string  _pfx_password;
    private readonly RSA     _rsa;

    public RsaService(IConfiguration config)
    {
        var private_key = config["Rsa:PrivateKey"];
        if (string.IsNullOrEmpty(private_key))
            throw new InvalidOperationException("❌ Rsa:PrivateKey no configurada.");

        _rsa = RSA.Create();
        _rsa.ImportRSAPrivateKey(Convert.FromBase64String(private_key), out _);

        var pfx_b64   = config["Pfx:Base64"]   ?? throw new InvalidOperationException("❌ Pfx:Base64 no configurada.");
        _pfx_password = config["Pfx:Password"] ?? throw new InvalidOperationException("❌ Pfx:Password no configurada.");
        _pfx_bytes    = Convert.FromBase64String(pfx_b64);
    }

    public byte[] FirmarPdfConCertificado(
        byte[] pdf_bytes,
        float x      = 36f,
        float y      = 210f,
        float ancho  = 220f,
        float alto   = 55f,
        int   pagina = 1)
    {
        var pkcs12 = new Pkcs12StoreBuilder().Build();
        using var pfx_stream = new MemoryStream(_pfx_bytes);
        pkcs12.Load(pfx_stream, _pfx_password.ToCharArray());

        string alias = "";
        foreach (string a in pkcs12.Aliases)
        {
            if (pkcs12.IsKeyEntry(a)) { alias = a; break; }
        }

        var pk_entry   = pkcs12.GetKey(alias);
        var cert_chain = pkcs12.GetCertificateChain(alias);
        var pk         = pk_entry.Key;

        IX509Certificate[] chain = cert_chain
            .Select(c => (IX509Certificate)new X509CertificateBC(c.Certificate))
            .ToArray();

        using var src_stream  = new MemoryStream(pdf_bytes);
        using var dest_stream = new MemoryStream();

        var reader  = new PdfReader(src_stream);
        var stamper = new PdfSigner(reader, dest_stream, new StampingProperties());

        stamper.SetReason("UMG Basic Rover 2.0 - 2026");
        stamper.SetLocation("Guatemala");
        stamper.SetContact("NextTech Solutions UMG");
        stamper.SetPageNumber(pagina);
        stamper.SetPageRect(new iText.Kernel.Geom.Rectangle(x, y, x + ancho, y + alto));
        stamper.SetFieldName("NextTechSignature");

        // Apariencia con fuente pequeña — nueva API iText7 v8
        var firma_appearance = new iText.Forms.Form.Element.SignatureFieldAppearance("NextTechSignature");
        firma_appearance.SetFontSize(6f);
        stamper.SetSignatureAppearance(firma_appearance);

        // ← ESTE BLOQUE ES CRÍTICO — firma el PDF
        var signer = new PrivateKeySignature(new PrivateKeyBC(pk), "SHA-256");
        stamper.SignDetached(
            new BouncyCastleDigest(),
            signer,
            chain,
            null, null, null,
            0,
            PdfSigner.CryptoStandard.CMS
        );

        return dest_stream.ToArray();
    }

    public static string ComputarHashPdf(byte[] pdf_bytes)
    {
        var hash = SHA256.HashData(pdf_bytes);
        return Convert.ToHexString(hash).ToLower();
    }

    public bool VerificarFirma(byte[] contenido, string firma_base64)
    {
        try
        {
            var firma_bytes = Convert.FromBase64String(firma_base64.Trim());
            return _rsa.VerifyData(contenido, firma_bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch { return false; }
    }

    public string ObtenerClavePublica()
        => Convert.ToBase64String(_rsa.ExportRSAPublicKey());

    public string FirmarBytes(byte[] contenido)
    {
        var firma = _rsa.SignData(contenido, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(firma);
    }
}