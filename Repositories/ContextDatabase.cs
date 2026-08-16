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

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
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
