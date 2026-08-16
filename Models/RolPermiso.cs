using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MSMultilider.Seguridad.Models
{
    [Table("rol_permiso")]
    public class RolPermiso
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Column("rol_id")]
        public int RolId { get; set; }

        [Column("permiso_id")]
        public int PermisoId { get; set; }

        [Column("created_at")]
        public DateTime? CreatedAt { get; set; }

        [Column("updated_at")]
        public DateTime? UpdatedAt { get; set; }

        public Rol Rol { get; set; } = null!;
        public Permiso Permiso { get; set; } = null!;
        public ICollection<RolPermisoUsuario> RolPermisoUsuarios { get; set; } = new List<RolPermisoUsuario>();
    }
}
