using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MSMultilider.Seguridad.Models
{
    [Table("rol_permiso_usuario")]
    public class RolPermisoUsuario
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Column("user_id")]
        public int UserId { get; set; }

        [Column("rol_permiso_id")]
        public int RolPermisoId { get; set; }

        [Column("created_at")]
        public DateTime? CreatedAt { get; set; }

        [Column("updated_at")]
        public DateTime? UpdatedAt { get; set; }

        public Usuario Usuario { get; set; } = null!;
        public RolPermiso RolPermiso { get; set; } = null!;
    }
}
