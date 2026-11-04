using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace MSMultilider.Seguridad.Models;
[Table("auth_sessions")]
public sealed class AuthSession {
    [Key, MaxLength(36), Column("jti")] public string Jti { get; set; } = "";
    [Column("user_id")] public int UserId { get; set; }
    [Column("version")] public long Version { get; set; }
    [Column("expires_at")] public DateTime ExpiresAt { get; set; }
    [Column("revoked_at")] public DateTime? RevokedAt { get; set; }
}
