using firma_electronica_api;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

var port = Environment.GetEnvironmentVariable("PORT") ?? "8081";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("allow_all", policy =>
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

// Swagger
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

// Registrar RsaService
builder.Services.AddSingleton<RsaService>();

var app = builder.Build();

app.UseCors("allow_all");
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "UMG Firma Electronica API v1");
    c.RoutePrefix = "swagger";
});

// ── Health check ─────────────────────────────────────────
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
app.MapPost("/sign", async (IFormFile? pdf, HttpRequest request, RsaService rsa) =>
{
    var api_key  = request.Headers["X-Api-Key"].ToString();
    var expected = builder.Configuration["Api:Key"] ?? "dev-key";

    if (api_key != expected)
        return Results.Unauthorized();

    if (pdf is null || pdf.Length == 0)
        return Results.BadRequest(new { error = "Archivo PDF requerido." });

    using var ms = new MemoryStream();
    await pdf.CopyToAsync(ms);
    var pdf_bytes = ms.ToArray();

    var firma = rsa.FirmarBytes(pdf_bytes);

    return Results.Ok(new
    {
        firma,
        algoritmo    = "RSA-2048 SHA-256 PKCS1",
        fecha_firma  = DateTime.UtcNow,
        tamano_bytes = pdf_bytes.Length
    });
}).WithTags("Firma").DisableAntiforgery();
// ── Verificar PDF ─────────────────────────────────────────
app.MapPost("/verify", async (IFormFile? pdf, HttpRequest request, RsaService rsa) =>
{
    var form  = await request.ReadFormAsync();
    var firma = form["firma"].ToString();

    if (pdf is null || pdf.Length == 0)
        return Results.BadRequest(new { error = "Archivo PDF requerido." });

    if (string.IsNullOrWhiteSpace(firma))
        return Results.BadRequest(new { error = "Firma requerida." });

    using var ms = new MemoryStream();
    await pdf.CopyToAsync(ms);
    var pdf_bytes = ms.ToArray();

    var es_valido = rsa.VerificarFirma(pdf_bytes, firma);

    return Results.Ok(new
    {
        valido    = es_valido,
        mensaje   = es_valido
            ? "✅ Documento auténtico — la firma es válida."
            : "❌ Documento modificado — la firma no coincide.",
        algoritmo = "RSA-2048 SHA-256 PKCS1"
    });
}).WithTags("Firma").DisableAntiforgery();
app.Run();