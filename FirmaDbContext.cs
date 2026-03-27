using Microsoft.EntityFrameworkCore;

namespace firma_electronica_api;

// ── Entidad: firmas ───────────────────────────────────────
public class FirmaRegistrada
{
    public int      id       { get; set; }
    public string   hash_pdf { get; set; } = string.Empty;
    public string   firma    { get; set; } = string.Empty;
    public string   cliente  { get; set; } = string.Empty;
    public DateTime fecha    { get; set; } = DateTime.UtcNow;
}

// ── Entidad: clientes ─────────────────────────────────────
public class ClienteApi
{
    public int      id             { get; set; }
    public string   nombre         { get; set; } = string.Empty;
    public string   api_key        { get; set; } = string.Empty;
    public bool     activo         { get; set; } = true;
    public DateTime fecha_creacion { get; set; } = DateTime.UtcNow;
}

// ── DbContext ─────────────────────────────────────────────
public class FirmaDbContext : DbContext
{
    public FirmaDbContext(DbContextOptions<FirmaDbContext> options) : base(options) { }

    public DbSet<FirmaRegistrada> firmas   { get; set; } = null!;
    public DbSet<ClienteApi>      clientes { get; set; } = null!;

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
            e.Property(f => f.cliente).HasMaxLength(100);
        });

        modelBuilder.Entity<ClienteApi>(e =>
        {
            e.ToTable("clientes_api");
            e.HasKey(c => c.id);
            e.Property(c => c.id).UseIdentityAlwaysColumn();
            e.HasIndex(c => c.api_key).IsUnique();
            e.Property(c => c.nombre).IsRequired().HasMaxLength(100);
            e.Property(c => c.api_key).IsRequired().HasMaxLength(64);
        });
    }
}