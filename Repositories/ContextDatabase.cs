using Microsoft.EntityFrameworkCore;
using MSMultilider.Seguridad.Models;

namespace MSMultilider.Seguridad.Repositories
{
    public class ContextDatabase : DbContext
    {
        public ContextDatabase(DbContextOptions<ContextDatabase> options) : base(options) { }

        public DbSet<Usuario> Usuarios { get; set; }
        public DbSet<Rol> Roles { get; set; }
        public DbSet<Permiso> Permisos { get; set; }
        public DbSet<RolPermiso> RolPermisos { get; set; }
        public DbSet<RolPermisoUsuario> RolPermisoUsuarios { get; set; }

        public DbSet<AuthSession> AuthSessions { get; set; }

        public async Task LockAuthority(CancellationToken ct) {
            if(Database.ProviderName?.Contains("MySql")==true)
                await Database.ExecuteSqlRawAsync("SELECT id FROM auth_mutex WHERE id = 1 FOR UPDATE",ct);
        }

        public override async Task<int> SaveChangesAsync(CancellationToken ct = default)
        {
            await using var owned=Database.CurrentTransaction is null ? await Database.BeginTransactionAsync(ct) : null;
            await LockAuthority(ct);
            // Version changes and their data mutations share a transaction. No stale permission claims.
            ChangeTracker.DetectChanges();
            var users = ChangeTracker.Entries<Usuario>().Where(e=>e.State==EntityState.Modified &&
                (e.Property(x=>x.Password).IsModified || e.Property(x=>x.Estado).IsModified)).Select(e=>e.Entity.Id).ToHashSet();
            var roleIds=ChangeTracker.Entries<Rol>().Where(e=>(e.State==EntityState.Modified && (e.Property(x=>x.Nombre).IsModified || e.Property(x=>x.Estado).IsModified)) || e.State==EntityState.Deleted).Select(e=>e.Entity.Id).ToArray();
            var permissionIds=ChangeTracker.Entries<Permiso>().Where(e=>(e.State==EntityState.Modified && (e.Property(x=>x.Nombre).IsModified || e.Property(x=>x.Estado).IsModified)) || e.State==EntityState.Deleted).Select(e=>e.Entity.Id).ToArray();
            var linkIds=ChangeTracker.Entries<RolPermiso>().Where(e=>e.State==EntityState.Deleted || e.State==EntityState.Modified).Select(e=>e.Entity.Id).ToArray();
            foreach(var e in ChangeTracker.Entries<RolPermisoUsuario>().Where(e=>e.State!=EntityState.Unchanged)) users.Add(e.Entity.UserId);
            if(roleIds.Length+permissionIds.Length+linkIds.Length>0) {
                var affected=await RolPermisoUsuarios.Where(x=>roleIds.Contains(x.RolPermiso.RolId) || permissionIds.Contains(x.RolPermiso.PermisoId) || linkIds.Contains(x.RolPermisoId)).Select(x=>x.UserId).Distinct().ToListAsync(ct);
                users.UnionWith(affected);
            }
            foreach(var id in users.Where(x=>x>0)) {
                var user=Usuarios.Local.FirstOrDefault(x=>x.Id==id) ?? await Usuarios.SingleOrDefaultAsync(x=>x.Id==id,ct);
                if(user is not null && Entry(user).State!=EntityState.Deleted) user.AuthVersion++;
            }
            var result=await base.SaveChangesAsync(ct);
            if(owned is not null) await owned.CommitAsync(ct);
            return result;
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<OperationGrant>().HasIndex(x=>x.UserId);
            modelBuilder.Entity<ProfileIdentityReceipt>().HasKey(x=>x.Id);
            modelBuilder.Entity<ProfileBinding>().HasKey(x=>x.Id);
            modelBuilder.Entity<OperationGrant>().HasIndex(x=>x.ParentId);
            modelBuilder.Entity<Usuario>().Property(x=>x.AuthVersion).IsConcurrencyToken();
            modelBuilder.Entity<AuthSession>().HasIndex(x=>x.ExpiresAt);
            modelBuilder.Entity<AuthSession>().HasIndex(x=>x.UserId);
            modelBuilder.Entity<Usuario>().HasIndex(x=>x.Correo).IsUnique();

            modelBuilder.Entity<RolPermiso>()
                .HasOne(rp => rp.Rol)
                .WithMany(r => r.RolPermisos)
                .HasForeignKey(rp => rp.RolId);

            modelBuilder.Entity<RolPermiso>()
                .HasOne(rp => rp.Permiso)
                .WithMany(p => p.RolPermisos)
                .HasForeignKey(rp => rp.PermisoId);

            modelBuilder.Entity<RolPermisoUsuario>()
                .HasOne(rpu => rpu.Usuario)
                .WithMany(u => u.RolPermisoUsuarios)
                .HasForeignKey(rpu => rpu.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RolPermisoUsuario>()
                .HasOne(rpu => rpu.RolPermiso)
                .WithMany(rp => rp.RolPermisoUsuarios)
                .HasForeignKey(rpu => rpu.RolPermisoId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
