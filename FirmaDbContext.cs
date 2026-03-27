using Microsoft.EntityFrameworkCore;

namespace firma_electronica_api;

// ── Entidad ───────────────────────────────────────────────
public class FirmaRegistrada
{
    public int    id       { get; set; }  // SERIAL PRIMARY KEY
    public string hash_pdf { get; set; } = string.Empty; // SHA-256 del PDF (UNIQUE)
    public string firma    { get; set; } = string.Empty; // Firma RSA en base64
    public string cliente  { get; set; } = string.Empty; // API Key que la generó (primeros 8 chars)
    public DateTime fecha  { get; set; } = DateTime.UtcNow;
}

// ── DbContext ─────────────────────────────────────────────
public class FirmaDbContext : DbContext
{
    public FirmaDbContext(DbContextOptions<FirmaDbContext> options) : base(options) { }

    public DbSet<FirmaRegistrada> firmas { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<FirmaRegistrada>(e =>
        {
            e.ToTable("firmas_registradas");
            e.HasKey(f => f.id);
            e.Property(f => f.id).UseIdentityAlwaysColumn();
            e.HasIndex(f => f.hash_pdf).IsUnique();
            e.Property(f => f.hash_pdf).IsRequired().HasMaxLength(64);
            e.Property(f => f.firma).IsRequired();
            e.Property(f => f.cliente).HasMaxLength(20);
        });
    }
}