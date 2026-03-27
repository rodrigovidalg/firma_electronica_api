using firma_electronica_api;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

var port = Environment.GetEnvironmentVariable("PORT") ?? "8081";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// ── PostgreSQL ────────────────────────────────────────────
var connection_string = builder.Configuration.GetConnectionString("default_connection");

// Railway inyecta DATABASE_URL — si no hay connection string configurada, lo leemos directo
if (string.IsNullOrEmpty(connection_string))
    connection_string = Environment.GetEnvironmentVariable("DATABASE_URL");

if (string.IsNullOrEmpty(connection_string))
    throw new InvalidOperationException("❌ No se encontró connection string para PostgreSQL.");

builder.Services.AddDbContext<FirmaDbContext>(options =>
    options.UseNpgsql(connection_string));

// ── CORS ──────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("allow_all", policy =>
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

// ── Swagger ───────────────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title       = "UMG Firma Electronica API",
        Version     = "v1",
        Description = "Microservicio de firma electronica avanzada RSA-2048 — UMG Basic Rover 2.0-2026"
    });
});

// ── RsaService (Singleton — la clave privada no cambia) ───
builder.Services.AddSingleton<RsaService>();

var app = builder.Build();

// ── Migrar BD automáticamente al iniciar ─────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<FirmaDbContext>();
    db.Database.EnsureCreated(); // Crea la tabla si no existe
}

app.UseCors("allow_all");
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "UMG Firma Electronica API v1");
    c.RoutePrefix = "swagger";
});

// ── Health check ──────────────────────────────────────────
app.MapGet("/health", () => Results.Ok(new
{
    status  = "healthy",
    service = "UMG Firma Electronica API",
    version = "1.0"
})).WithTags("Health");

// ── Clave pública ─────────────────────────────────────────
app.MapGet("/public-key", (RsaService rsa) =>
{
    return Results.Ok(new
    {
        clave_publica = rsa.ObtenerClavePublica(),
        algoritmo     = "RSA-2048 SHA-256 PKCS1"
    });
}).WithTags("Firma");

// ── Firmar PDF ────────────────────────────────────────────
// El consumidor manda solo el PDF.
// La API firma, guarda hash→firma en BD y confirma.
app.MapPost("/sign", async (HttpRequest request, RsaService rsa, FirmaDbContext db) =>
{
    var api_key  = request.Headers["X-Api-Key"].ToString();
    var expected = builder.Configuration["Api:Key"] ?? "dev-key";

    if (api_key != expected)
        return Results.Unauthorized();

    var form = await request.ReadFormAsync();
    var pdf  = form.Files.GetFile("pdf");

    if (pdf is null || pdf.Length == 0)
        return Results.BadRequest(new { error = "Archivo PDF requerido." });

    using var ms = new MemoryStream();
    await pdf.CopyToAsync(ms);
    var pdf_bytes = ms.ToArray();

    var hash_pdf = RsaService.ComputarHashPdf(pdf_bytes);

    // Si ya existe una firma para este PDF exacto, la reutilizamos
    var existente = await db.firmas.FirstOrDefaultAsync(f => f.hash_pdf == hash_pdf);
    if (existente != null)
    {
        return Results.Ok(new
        {
            mensaje      = "✅ PDF ya estaba firmado — firma recuperada.",
            algoritmo    = "RSA-2048 SHA-256 PKCS1",
            fecha_firma  = existente.fecha,
            tamano_bytes = pdf_bytes.Length
        });
    }

    // Firmar y guardar en BD
    var firma = rsa.FirmarBytes(pdf_bytes);

    db.firmas.Add(new FirmaRegistrada
    {
        hash_pdf = hash_pdf,
        firma    = firma,
        cliente  = api_key.Length >= 8 ? api_key[..8] : api_key,
        fecha    = DateTime.UtcNow
    });
    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        mensaje      = "✅ PDF firmado y registrado correctamente.",
        algoritmo    = "RSA-2048 SHA-256 PKCS1",
        fecha_firma  = DateTime.UtcNow,
        tamano_bytes = pdf_bytes.Length
    });
}).WithTags("Firma").DisableAntiforgery();

// ── Verificar PDF ─────────────────────────────────────────
// El consumidor manda SOLO el PDF.
// La API busca la firma en BD y verifica con RSA.
app.MapPost("/verify", async (HttpRequest request, RsaService rsa, FirmaDbContext db) =>
{
    var form = await request.ReadFormAsync();
    var pdf  = form.Files.GetFile("pdf");

    if (pdf is null || pdf.Length == 0)
        return Results.BadRequest(new { error = "Archivo PDF requerido." });

    using var ms = new MemoryStream();
    await pdf.CopyToAsync(ms);
    var pdf_bytes = ms.ToArray();

    var hash_pdf = RsaService.ComputarHashPdf(pdf_bytes);

    // Buscar firma en BD por hash del PDF
    var registro = await db.firmas.FirstOrDefaultAsync(f => f.hash_pdf == hash_pdf);

    if (registro is null)
    {
        return Results.Ok(new
        {
            valido    = false,
            mensaje   = "❌ Este PDF no fue generado por este sistema o fue modificado.",
            algoritmo = "RSA-2048 SHA-256 PKCS1"
        });
    }

    // Verificar con RSA que la firma del registro corresponde a este PDF
    var es_valido = rsa.VerificarFirma(pdf_bytes, registro.firma);

    return Results.Ok(new
    {
        valido      = es_valido,
        mensaje     = es_valido
            ? "✅ Documento auténtico — firma RSA válida."
            : "❌ Documento modificado — la firma no coincide.",
        algoritmo   = "RSA-2048 SHA-256 PKCS1",
        fecha_firma = registro.fecha
    });
}).WithTags("Firma").DisableAntiforgery();

app.Run();