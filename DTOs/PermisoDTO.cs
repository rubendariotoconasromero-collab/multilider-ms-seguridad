using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
namespace MSMultilider.Seguridad.DTOs
{
    public class PermisoDTO
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public string? Descripcion { get; set; }
        public bool Estado { get; set; }
    }

    public class PermisoCreateDTO
    {
        [Required, StringLength(100)] public string Nombre { get; set; } = string.Empty;
        [StringLength(255)] public string? Descripcion { get; set; }
        public bool Estado { get; set; } = true;
    }
}
