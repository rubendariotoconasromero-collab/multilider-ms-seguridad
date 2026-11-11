using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Multilider.Operations;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;
namespace MSMultilider.Seguridad.Controllers;

[ApiController]
public sealed class OperationsController(ContextDatabase db,IConfiguration config):ControllerBase {
    private string Dataset=>config["Operations:Dataset"]??throw new ProtocolException("Configura Operations:Dataset.");
    private static string Permission(string kind)=>kind switch{
        "venta" or "anulacion"=>"acceso_ventas","cliente"=>"acceso_clientes","asesor"=>"acceso_asesores",
        _=>throw new ProtocolException("Tipo de operación inválido.",422)};
    private async Task<bool> Active(OperationGrant grant,CancellationToken ct) {
        var u=await db.Usuarios.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==grant.UserId,ct);
        var session=await db.AuthSessions.AsNoTracking().SingleOrDefaultAsync(x=>x.Jti==grant.SessionJti,ct);
        return u is not null && u.Estado && u.AuthVersion==grant.UserVersion &&
            session is not null && session.RevokedAt is null && session.ExpiresAt>DateTime.UtcNow &&
            await db.RolPermisoUsuarios.AnyAsync(x=>x.UserId==grant.UserId && x.RolPermiso.Rol.Estado && x.RolPermiso.Permiso.Estado &&
                x.RolPermiso.Permiso.Nombre==Permission(grant.Kind),ct);
    }
    private async Task<OperationGrant> Find(Guid id,CancellationToken ct) {
        var grant=await db.Set<OperationGrant>().FindAsync([id.ToString("D")],ct)??throw new ProtocolException("Operación no admitida.",404);
        if(grant.Dataset!=Dataset)throw new ProtocolException("Instalación de operación incorrecta.",403);
        return grant;
    }
    private async Task<OperationAuthorization> Reply(OperationGrant g,CancellationToken ct) {
        var owner=g.ParentId is null?g:await Find(Guid.Parse(g.ParentId),ct);
        return new(Guid.Parse(g.Id),g.Kind,g.ResourceId,g.PayloadHash,config["Jwt:Issuer"]!,g.UserId.ToString(),g.State,
            g.ParentId is null?null:Guid.Parse(g.ParentId),config["Jwt:Issuer"],owner.UserId.ToString(),Dataset);
    }
    [HttpPost("api/auth/operaciones"),Authorize]
    public async Task<IActionResult> Admit([FromBody]OperationAdmission r,CancellationToken ct) {
        await OperationProtocol.Caller(HttpContext,config,"comercial");
        if(r.OperationId==Guid.Empty || r.ResourceId<=0 || r.PayloadHash.Length!=64 || !r.PayloadHash.All(Uri.IsHexDigit) ||
            !User.HasClaim("permission",Permission(r.Kind)))throw new ProtocolException("Operación o permiso inválido.",403);
        await using var tx=db.Database.CurrentTransaction is null?await db.Database.BeginTransactionAsync(ct):null;await db.LockAuthority(ct);
        var id=r.OperationId.ToString("D");var user=int.Parse(User.FindFirstValue("sub")!);
        var previous=await db.Set<OperationGrant>().FindAsync([id],ct);
        if(r.Kind=="anulacion") {
            if(r.ParentOperationId is null)throw new ProtocolException("Falta venta de origen.",422);
            var parent=await Find(r.ParentOperationId.Value,ct);
            var eligibleParent = parent.Kind=="venta" && parent.State=="Confirmando"
                || parent.Kind=="venta_importada" && parent.State=="Importada";
            if(!eligibleParent || parent.ResourceId!=r.ResourceId)
                throw new ProtocolException("Venta de origen incompatible.",409);
        } else if(r.ParentOperationId is not null)throw new ProtocolException("Vínculo no permitido.",422);
        if(previous is not null) {
            if(previous.UserId!=user || previous.Kind!=r.Kind || previous.PayloadHash!=r.PayloadHash ||
                previous.ResourceId!=r.ResourceId || previous.Dataset!=Dataset || previous.ParentId!=r.ParentOperationId?.ToString("D"))
                throw new ProtocolException("UUID ya utilizado por otros datos o actor.",409);
            // Reauthorization of an admitted intent by its owner; no terminal decision can change.
            if(previous.State=="Admitida"){previous.SessionJti=User.FindFirstValue("jti")!;previous.UserVersion=long.Parse(User.FindFirstValue("ver")!);}
        } else {
            previous=new OperationGrant{Id=id,Kind=r.Kind,ResourceId=r.ResourceId,PayloadHash=r.PayloadHash,Dataset=Dataset,
                UserId=user,UserVersion=long.Parse(User.FindFirstValue("ver")!),SessionJti=User.FindFirstValue("jti")!,
                ParentId=r.ParentOperationId?.ToString("D")};
            db.Add(previous);
        }
        await db.SaveChangesAsync(ct);if(tx is not null)await tx.CommitAsync(ct);
        return new JsonResult(await Reply(previous,ct),OperationProtocol.Json);
    }
    [HttpPost("internal/operations/v1/authorize"),AllowAnonymous]
    public async Task<IActionResult> Check([FromBody]OperationCheck r,CancellationToken ct) {
        var caller=await OperationProtocol.Caller(HttpContext,config);
        var allowed=caller switch{
            "comercial"=>new[]{"read","pivot","abort","cancel-pivot","identity"},
            "propiedades"=>new[]{"reserve","renew","confirm","release","reverse","read"},
            "finanzas"=>new[]{"prepare","activate","abort-finance","close","read"},
            _=>Array.Empty<string>()};
        if(!allowed.Contains(r.Action))throw new ProtocolException("Scope no permitido.",403);
        await using var tx=db.Database.CurrentTransaction is null?await db.Database.BeginTransactionAsync(ct):null;await db.LockAuthority(ct);
        var grant=await Find(r.OperationId,ct);
        if(r.Action is "pivot" or "cancel-pivot") {
            if(grant.Kind!=(r.Action=="pivot"?"venta":"anulacion"))throw new ProtocolException("Tipo de decisión incompatible.",403);
            if(grant.State=="Admitida") {
                if(!await Active(grant,ct))throw new ProtocolException("Reautoriza la operación con una sesión vigente.",403);
                grant.State=r.Action=="pivot"?"Confirmando":"Anulando";grant.UpdatedAt=DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
            }
            if(grant.State!=(r.Action=="pivot"?"Confirmando":"Anulando"))throw new ProtocolException("Decisión terminal incompatible.",409);
        } else {
            var valid=r.Action switch {
                "read"=>true,
                "reserve" or "renew" or "prepare"=>grant.Kind=="venta" && grant.State=="Admitida" && await Active(grant,ct),
                "confirm" or "activate"=>grant.Kind=="venta" && grant.State=="Confirmando",
                "close"=>grant.Kind=="anulacion" && grant.State=="Anulando",
                "reverse"=>grant.Kind=="anulacion" && grant.State=="Anulando",
                "release" or "abort-finance"=>grant.Kind=="venta" && grant.State=="Abortada",
                "identity"=>grant.Kind is "cliente" or "asesor" && grant.State=="Admitida" && await Active(grant,ct),
                "abort"=>caller=="comercial" && grant.Kind=="venta" && grant.State is "Admitida" or "Abortada",
                _=>false};
            if(!valid)throw new ProtocolException("La autorización no permite este paso.",403);
            if(r.Action=="abort" && grant.State=="Admitida"){grant.State="Abortada";grant.UpdatedAt=DateTime.UtcNow;await db.SaveChangesAsync(ct);}
        }
        if(tx is not null)await tx.CommitAsync(ct);return new JsonResult(await Reply(grant,ct),OperationProtocol.Json);
    }
}
