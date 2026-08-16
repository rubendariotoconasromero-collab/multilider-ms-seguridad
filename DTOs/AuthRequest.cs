using System.ComponentModel.DataAnnotations;

namespace MSMultilider.Seguridad.DTOs
{
    public class AuthRequest
    {
        [Required]
        [EmailAddress]
        public string Correo { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
