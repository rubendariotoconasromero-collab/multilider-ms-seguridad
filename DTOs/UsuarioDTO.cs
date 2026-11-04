using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
namespace MSMultilider.Seguridad.DTOs
{
    public class UsuarioDTO
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public string Correo { get; set; } = string.Empty;
        public bool Estado { get; set; }
        public List<RolPermisoAsignadoDTO> RolesPermisos { get; set; } = new();
    }

    public class UsuarioCreateDTO
    {
        [Required, StringLength(255)] public string Nombre { get; set; } = string.Empty;
        [Required, EmailAddress, StringLength(255)] public string Correo { get; set; } = string.Empty;
        [Required] public string Password { get; set; } = string.Empty;
        public bool Estado { get; set; } = true;
    }

    public class UsuarioUpdateDTO
    {
        [MinLength(1), StringLength(255)] public string? Nombre { get; set; }
        [EmailAddress, StringLength(255)] public string? Correo { get; set; }
        public string? Password { get; set; }
        public bool? Estado { get; set; }
    }

    public class RolPermisoAsignadoDTO
    {
        public int RolPermisoId { get; set; }
        public int RolId { get; set; }
        public string NombreRol { get; set; } = string.Empty;
        public int PermisoId { get; set; }
        public string NombrePermiso { get; set; } = string.Empty;
    }

    public class LoginResponseDTO
    {
        public string Message { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
        public string TokenType { get; set; } = "Bearer";
        public UsuarioDTO User { get; set; } = null!;
    }

    public class SyncAsignacionesDTO
    {
        [Required, JsonRequired] public List<int> RolPermisoIds { get; set; } = new();
    }
}
