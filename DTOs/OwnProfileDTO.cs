using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
namespace MSMultilider.Seguridad.DTOs;
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class OwnProfileDTO {
    [Required, StringLength(255)] public string Nombre { get; set; } = "";
    [Required, EmailAddress, StringLength(255)] public string Correo { get; set; } = "";
}
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class OwnPasswordDTO {
    [Required, JsonPropertyName("password_actual")] public string Actual { get; set; } = "";
    [Required, JsonPropertyName("password_nuevo")] public string Nuevo { get; set; } = "";
    [Required, JsonPropertyName("password_nuevo_confirmation")] public string Confirmation { get; set; } = "";
    public static bool Strong(string password) => password.Length>=8 && password.Any(char.IsUpper) &&
        password.Any(char.IsLower) && password.Any(char.IsDigit) && password.Any(c=>!char.IsLetterOrDigit(c));
}
