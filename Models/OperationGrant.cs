using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace MSMultilider.Seguridad.Models;
[Table("operation_grants")]
public sealed class OperationGrant {
    [Key,MaxLength(36)]public string Id{get;set;}="";
    [MaxLength(36)]public string? ParentId{get;set;}
    [MaxLength(32)]public string Kind{get;set;}="";
    public int ResourceId{get;set;}
    [MaxLength(64)]public string PayloadHash{get;set;}="";
    [MaxLength(100)]public string Dataset{get;set;}="";
    public int UserId{get;set;}
    public long UserVersion{get;set;}
    [MaxLength(36)]public string SessionJti{get;set;}="";
    [MaxLength(32)]public string State{get;set;}="Admitida";
    public DateTime CreatedAt{get;set;}=DateTime.UtcNow;
    public DateTime UpdatedAt{get;set;}=DateTime.UtcNow;
}
