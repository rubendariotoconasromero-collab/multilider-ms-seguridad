using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace MSMultilider.Seguridad.Models;
[Table("profile_bindings")]
public sealed class ProfileBinding {
    [Key,MaxLength(150)]public string Id{get;set;}="";
    public int UserId{get;set;}
    [MaxLength(36)]public string LastOperation{get;set;}="";
    [MaxLength(64)]public string Hash{get;set;}="";
    public long ActivationVersion{get;set;}
}
[Table("profile_identity_receipts")]
public sealed class ProfileIdentityReceipt {
    [Key,MaxLength(36)]public string Id{get;set;}="";
    public int UserId{get;set;}
    [MaxLength(64)]public string Hash{get;set;}="";
}
