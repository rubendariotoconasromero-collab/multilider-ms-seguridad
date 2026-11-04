using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
namespace MSMultilider.Seguridad.DTOs
{
    public class RolDTO
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public string? Descripcion { get; set; }
        public bool Estado { get; set; }
        public List<PermisoDTO> Permisos { get; set; } = new();
    }

    public class RolCreateDTO
    {
        [Required, StringLength(100)] public string Nombre { get; set; } = string.Empty;
        [StringLength(255)] public string? Descripcion { get; set; }
        public bool Estado { get; set; } = true;
    }

    public class SyncPermisosDTO
    {
        [Required, JsonRequired] public List<int> Permisos { get; set; } = new();
    }
}
