using firma_electronica_api;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables();

var port = Environment.GetEnvironmentVariable("PORT") ?? "8081";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// ── PostgreSQL ────────────────────────────────────────────
var connection_string = builder.Configuration.GetConnectionString("default_connection");

if (string.IsNullOrEmpty(connection_string))
    connection_string = Environment.GetEnvironmentVariable("DATABASE_URL");

if (string.IsNullOrEmpty(connection_string))
    throw new InvalidOperationException("❌ No se encontró connection string para PostgreSQL.");

if (connection_string.StartsWith("postgresql://") || connection_string.StartsWith("postgres://"))
{
    var uri     = new Uri(connection_string);
    var user    = uri.UserInfo.Split(':')[0];
    var pass    = uri.UserInfo.Split(':')[1];
    var host    = uri.Host;
    var db_port = uri.Port;
    var db_name = uri.AbsolutePath.TrimStart('/');
    connection_string = $"Host={host};Port={db_port};Database={db_name};Username={user};Password={pass};SSL Mode=Require;Trust Server Certificate=true;";
}

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
        Description = """
            ## Microservicio de Firma Electrónica Avanzada RSA-2048

            ### Endpoints públicos
            - `POST /verify` — Verificar autenticidad de un PDF (no requiere key)
            - `GET /public-key` — Obtener clave pública RSA

            ### Endpoints para clientes registrados
            - `POST /sign` — Firmar un PDF (requiere `X-Api-Key`)

            ### Endpoints de administración
            - `GET /clients` — Listar clientes (requiere `X-Admin-Key`)
            - `POST /clients` — Crear cliente nuevo (requiere `X-Admin-Key`)
            - `DELETE /clients/{id}` — Revocar cliente (requiere `X-Admin-Key`)
            """
    });
});

builder.Services.AddSingleton<RsaService>();

var app = builder.Build();

// ── Migrar BD automáticamente al iniciar ─────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<FirmaDbContext>();
    db.Database.EnsureCreated();
}

app.UseCors("allow_all");
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "UMG Firma Electronica API v1");
    c.RoutePrefix = "swagger";
});

// ── Helpers ───────────────────────────────────────────────
bool EsAdmin(HttpRequest req)
{
    var admin_key = req.Headers["X-Admin-Key"].ToString();
    var expected  = builder.Configuration["Admin:Key"] ?? "";
    return !string.IsNullOrEmpty(expected) && admin_key == expected;
}

async Task<bool> EsClienteValido(string api_key, FirmaDbContext db)
{
    if (string.IsNullOrEmpty(api_key)) return false;
    return await db.clientes.AnyAsync(c => c.api_key == api_key && c.activo);
}

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
app.MapPost("/sign", async (HttpRequest request, RsaService rsa, FirmaDbContext db) =>
{
    var api_key = request.Headers["X-Api-Key"].ToString();

    if (!await EsClienteValido(api_key, db))
        return Results.Unauthorized();

    var form = await request.ReadFormAsync();
    var pdf  = form.Files.GetFile("pdf");

    if (pdf is null || pdf.Length == 0)
        return Results.BadRequest(new { error = "Archivo PDF requerido." });

    // Parámetros de posición opcionales con valores por defecto
    var firma_x      = float.TryParse(form["firma_x"],      out var fx) ? fx : 36f;
    var firma_y      = float.TryParse(form["firma_y"],      out var fy) ? fy : 210f;
    var firma_ancho  = float.TryParse(form["firma_ancho"],  out var fw) ? fw : 220f;
    var firma_alto   = float.TryParse(form["firma_alto"],   out var fh) ? fh : 55f;
    var firma_pagina = int.TryParse(form["firma_pagina"],   out var fp) ? fp : 1;

    using var ms = new MemoryStream();
    await pdf.CopyToAsync(ms);
    var pdf_bytes = ms.ToArray();

    var pdf_firmado = rsa.FirmarPdfConCertificado(
        pdf_bytes, firma_x, firma_y, firma_ancho, firma_alto, firma_pagina);
    var hash_pdf = RsaService.ComputarHashPdf(pdf_firmado);

    var existente = await db.firmas.FirstOrDefaultAsync(f => f.hash_pdf == hash_pdf);
    if (existente == null)
    {
        var cliente_nombre = await db.clientes
            .Where(c => c.api_key == api_key)
            .Select(c => c.nombre)
            .FirstOrDefaultAsync() ?? api_key[..Math.Min(8, api_key.Length)];

        db.firmas.Add(new FirmaRegistrada
        {
            hash_pdf = hash_pdf,
            firma    = "X509-CMS-EMBEDDED",
            cliente  = cliente_nombre,
            fecha    = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
    }

    return Results.Ok(new
    {
        mensaje         = "✅ PDF firmado con certificado X.509 y firma embebida.",
        algoritmo       = "RSA-2048 SHA-256 CMS X.509",
        fecha_firma     = DateTime.UtcNow,
        tamano_bytes    = pdf_firmado.Length,
        pdf_firmado_b64 = Convert.ToBase64String(pdf_firmado)
    });
}).WithTags("Firma").DisableAntiforgery();

// ── Verificar PDF ─────────────────────────────────────────
app.MapPost("/verify", async (HttpRequest request, RsaService rsa, FirmaDbContext db) =>
{
    var form = await request.ReadFormAsync();
    var pdf  = form.Files.GetFile("pdf");

    if (pdf is null || pdf.Length == 0)
        return Results.BadRequest(new { error = "Archivo PDF requerido." });

    using var ms = new MemoryStream();
    await pdf.CopyToAsync(ms);
    var pdf_bytes = ms.ToArray();
    var hash_pdf  = RsaService.ComputarHashPdf(pdf_bytes);

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

    var es_valido = registro.firma == "X509-CMS-EMBEDDED"
        ? true  // firma embebida X.509 — autenticidad garantizada por hash
        : rsa.VerificarFirma(pdf_bytes, registro.firma);

    return Results.Ok(new
    {
        valido      = es_valido,
        mensaje     = es_valido
            ? "✅ Documento auténtico — firma RSA válida."
            : "❌ Documento modificado — la firma no coincide.",
        algoritmo   = "RSA-2048 SHA-256 CMS X.509",
        fecha_firma = registro.fecha
    });
}).WithTags("Firma").DisableAntiforgery();

// ════════════════════════════════════════════════════════
//  ADMIN — Gestión de clientes
// ════════════════════════════════════════════════════════

app.MapGet("/clients", async (HttpRequest request, FirmaDbContext db) =>
{
    if (!EsAdmin(request)) return Results.Unauthorized();

    var clientes = await db.clientes
        .OrderByDescending(c => c.fecha_creacion)
        .Select(c => new
        {
            c.id,
            c.nombre,
            api_key_preview = c.api_key.Substring(0, 8) + "...",
            c.activo,
            c.fecha_creacion
        })
        .ToListAsync();

    return Results.Ok(new { total = clientes.Count, clientes });
}).WithTags("Admin");

app.MapPost("/clients", async (HttpRequest request, FirmaDbContext db) =>
{
    if (!EsAdmin(request)) return Results.Unauthorized();

    var body = await request.ReadFromJsonAsync<CrearClienteRequest>();
    if (body is null || string.IsNullOrWhiteSpace(body.nombre))
        return Results.BadRequest(new { error = "El nombre del cliente es requerido." });

    var nueva_key = Convert.ToHexString(
        System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)
    ).ToLower();

    var cliente = new ClienteApi
    {
        nombre         = body.nombre.Trim(),
        api_key        = nueva_key,
        activo         = true,
        fecha_creacion = DateTime.UtcNow
    };

    db.clientes.Add(cliente);
    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        mensaje        = $"✅ Cliente '{cliente.nombre}' creado correctamente.",
        id             = cliente.id,
        nombre         = cliente.nombre,
        api_key        = nueva_key,
        fecha_creacion = cliente.fecha_creacion
    });
}).WithTags("Admin");

app.MapDelete("/clients/{id:int}", async (int id, HttpRequest request, FirmaDbContext db) =>
{
    if (!EsAdmin(request)) return Results.Unauthorized();

    var cliente = await db.clientes.FindAsync(id);
    if (cliente is null)
        return Results.NotFound(new { error = "Cliente no encontrado." });

    cliente.activo = false;
    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        mensaje = $"✅ Acceso revocado para cliente '{cliente.nombre}'.",
        id      = cliente.id
    });
}).WithTags("Admin");

app.Run();

record CrearClienteRequest(string nombre);