using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Multilider.Operations;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;
namespace MSMultilider.Seguridad.Controllers;
public sealed record ProfileCredential(string? Password);
[ApiController,Route("internal/identity/v1/operaciones"),AllowAnonymous]
public sealed class ProfileIdentityController(ContextDatabase db,OperationChannel channel,IConfiguration config):ControllerBase {
    private async Task<OperationGrant> Grant(Guid op,CancellationToken ct) {
        await OperationProtocol.Caller(HttpContext,config,"comercial");
        var grant=await db.Set<OperationGrant>().SingleOrDefaultAsync(x=>x.Id==op.ToString("D"),ct)??throw new ProtocolException("Operación no admitida.",404);
        if(grant.Kind is not ("cliente" or "asesor") || grant.Dataset!=config["Operations:Dataset"])throw new ProtocolException("Vínculo de otro origen.",403);
        return grant;
    }
    private string Key(OperationGrant grant)=>grant.Dataset+"|"+grant.Kind+"|"+grant.ResourceId;
    [HttpGet("{op:guid}")]
    public async Task<IActionResult> Get(Guid op,CancellationToken ct) {
        var grant=await Grant(op,ct);
        var receipt=await db.Set<ProfileIdentityReceipt>().FindAsync([grant.Id],ct)??throw new ProtocolException("Identidad pendiente.",404);
        if(receipt.Hash!=grant.PayloadHash)throw new ProtocolException("Operación incompatible.",409);
        return Ok(new{user_id=receipt.UserId,issuer=config["Jwt:Issuer"],subject=receipt.UserId.ToString()});
    }
    [HttpPost("{op:guid}/provision")]
    public async Task<IActionResult> Provision(Guid op,ProfileCredential credential,CancellationToken ct) {
        var grant=await Grant(op,ct);
        if(await db.Set<ProfileIdentityReceipt>().AsNoTracking().SingleOrDefaultAsync(x=>x.Id==grant.Id,ct) is {} replay) {
            if(replay.Hash!=grant.PayloadHash)throw new ProtocolException("Operación incompatible.",409);
            return Ok(new{user_id=replay.UserId,issuer=config["Jwt:Issuer"],subject=replay.UserId.ToString()});
        }
        // Read the prepared profile from its authority. Never persist credential in a command payload.
        var prepared=await channel.Send("comercial",HttpMethod.Get,$"internal/comercial/v1/perfiles/{op:D}",null,ct);
        if(prepared.GetProperty("payload_hash").GetString()!=grant.PayloadHash ||
            prepared.GetProperty("resource_id").GetInt32()!=grant.ResourceId)throw new ProtocolException("Perfil incompatible.",409);
        var profile=prepared.GetProperty("profile");var name=profile.GetProperty("nombre_completo").GetString()!;
        var email=profile.GetProperty("correo").GetString()!;
        var active=profile.TryGetProperty("estado",out var state)?state.ValueKind==JsonValueKind.True||state.ToString() is "1" or "true":true;
        if(string.IsNullOrWhiteSpace(name)||!System.Net.Mail.MailAddress.TryCreate(email,out _)||name.Length>255)throw new ProtocolException("Identidad inválida.",422);
        await using var tx=await db.Database.BeginTransactionAsync(ct);await db.LockAuthority(ct);
        var binding=await db.Set<ProfileBinding>().FindAsync([Key(grant)],ct);
        if(binding is not null && (!prepared.TryGetProperty("user_id",out var existing)||existing.ValueKind==JsonValueKind.Null||existing.GetInt32()!=binding.UserId))
            throw new ProtocolException("El perfil no contiene el vínculo previo; requiere conciliación explícita.",409);
        if(binding is not null&&binding.LastOperation==grant.Id) {
            if(binding.Hash!=grant.PayloadHash)throw new ProtocolException("UUID reutilizado.",409);
            return Ok(new{user_id=binding.UserId,issuer=config["Jwt:Issuer"],subject=binding.UserId.ToString()});
        }
        var actor=await db.Usuarios.AsNoTracking().SingleAsync(x=>x.Id==grant.UserId,ct);
        var session=await db.AuthSessions.AsNoTracking().SingleOrDefaultAsync(x=>x.Jti==grant.SessionJti,ct);
        if(!actor.Estado||actor.AuthVersion!=grant.UserVersion||session?.RevokedAt is not null||session is null||session.ExpiresAt<=DateTime.UtcNow)
            throw new ProtocolException("Reautoriza el cambio de perfil.",403);
        Usuario user;
        if(binding is null) {
            if(await db.Usuarios.AnyAsync(x=>x.Correo==email,ct))throw new ProtocolException("El correo pertenece a una identidad existente; requiere vínculo explícito.",409);
            // Preserve the existing client provisioning policy; adviser passwords retain strong validation.
            var password=grant.Kind=="cliente"?profile.GetProperty("ci").GetString():credential.Password;
            if(string.IsNullOrWhiteSpace(password)||grant.Kind=="asesor"&&!MSMultilider.Seguridad.DTOs.OwnPasswordDTO.Strong(password))
                throw new ProtocolException("Se requiere la contraseña del asesor para completar esta operación.",422);
            var role=await db.Roles.SingleOrDefaultAsync(x=>x.Nombre==(grant.Kind=="cliente"?"Cliente":"Asesor de Ventas")&&x.Estado,ct)
                ??throw new ProtocolException("Configura el rol de destino antes de activar perfiles.");
            if(await db.RolPermisos.AnyAsync(x=>x.RolId==role.Id&&
                (x.Permiso.Nombre=="acceso_usuarios"||x.Permiso.Nombre=="acceso_roles"||x.Permiso.Nombre=="acceso_permisos"),ct))
                throw new ProtocolException("El rol de perfil contiene administración de identidad; requiere asignación administrativa explícita.",409);
            user=new Usuario{Nombre=name,Correo=email,Password=BCrypt.Net.BCrypt.HashPassword(password),Estado=false,CreatedAt=DateTime.UtcNow};
            db.Usuarios.Add(user);await db.SaveChangesAsync(ct);
            foreach(var link in await db.RolPermisos.Where(x=>x.RolId==role.Id&&x.Permiso.Estado).ToListAsync(ct))
                db.RolPermisoUsuarios.Add(new RolPermisoUsuario{UserId=user.Id,RolPermisoId=link.Id});
            binding=new ProfileBinding{Id=Key(grant),UserId=user.Id};db.Add(binding);
        } else {
            user=await db.Usuarios.SingleAsync(x=>x.Id==binding.UserId,ct);
            if(await db.Usuarios.AnyAsync(x=>x.Correo==email&&x.Id!=user.Id,ct))throw new ProtocolException("Correo de otra identidad.",409);
            if(await db.RolPermisoUsuarios.AnyAsync(x=>x.UserId==user.Id&&(x.RolPermiso.Permiso.Nombre=="acceso_usuarios"||x.RolPermiso.Permiso.Nombre=="acceso_roles"||x.RolPermiso.Permiso.Nombre=="acceso_permisos"),ct))
                throw new ProtocolException("La identidad requiere gestión administrativa explícita.",409);
            user.Nombre=name;user.Correo=email;
            if(grant.Kind=="asesor"&&!string.IsNullOrEmpty(credential.Password)) {
                if(!MSMultilider.Seguridad.DTOs.OwnPasswordDTO.Strong(credential.Password))throw new ProtocolException("La contraseña del asesor no cumple la política.",422);
                user.Password=BCrypt.Net.BCrypt.HashPassword(credential.Password);
            }
        }
        // Activation follows proof that Comercial has durably bound this identity.
        user.Estado=false;binding.LastOperation=grant.Id;binding.Hash=grant.PayloadHash;
        await db.SaveChangesAsync(ct);
        binding.ActivationVersion=user.AuthVersion;
        db.Add(new ProfileIdentityReceipt{Id=grant.Id,UserId=user.Id,Hash=grant.PayloadHash});
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return Ok(new{user_id=user.Id,issuer=config["Jwt:Issuer"],subject=user.Id.ToString()});
    }
    [HttpPost("{op:guid}/activate")]
    public async Task<IActionResult> Activate(Guid op,CancellationToken ct) {
        var grant=await Grant(op,ct);
        var profile=await channel.Send("comercial",HttpMethod.Get,$"internal/comercial/v1/perfiles/{op:D}",null,ct);
        await using var tx=await db.Database.BeginTransactionAsync(ct);await db.LockAuthority(ct);
        var binding=await db.Set<ProfileBinding>().FindAsync([Key(grant)],ct)??throw new ProtocolException("Identidad pendiente.",409);
        if(binding.LastOperation!=grant.Id||profile.GetProperty("user_id").GetInt32()!=binding.UserId||
            profile.GetProperty("state").GetString() is not ("Vinculada" or "Completada"))throw new ProtocolException("Vínculo no confirmado.",409);
        var input=profile.GetProperty("profile");
        var active=!input.TryGetProperty("estado",out var enabled)||enabled.ValueKind==JsonValueKind.True||enabled.ToString() is "1" or "true";
        var user=await db.Usuarios.SingleAsync(x=>x.Id==binding.UserId,ct);
        if(user.AuthVersion!=binding.ActivationVersion)throw new ProtocolException("La identidad fue modificada o revocada; requiere revisión.",409);
        if(user.Estado!=active){user.Estado=active;await db.SaveChangesAsync(ct);binding.ActivationVersion=user.AuthVersion;await db.SaveChangesAsync(ct);}
        await tx.CommitAsync(ct);
        return Ok(new{estado=active});
    }
}
