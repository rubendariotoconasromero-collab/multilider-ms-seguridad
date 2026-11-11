using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Services;
using MSMultilider.Seguridad.Repositories;
using System.Security.Claims;
namespace MSMultilider.Seguridad.Controllers;
[ApiController, Route("api/auth")]
public class AuthController(ContextDatabase db,IUsuarioService users,IdentityProtocol identity):ControllerBase {
    private int Subject => int.Parse(User.FindFirstValue("sub")!);
    [HttpPost("login"), Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("login")]
    public async Task<IActionResult> Login(AuthRequest request,CancellationToken ct) {
        var user=db.Database.ProviderName?.Contains("MySql")==true
            ? (await db.Usuarios.FromSqlInterpolated($"SELECT * FROM users WHERE correo = {request.Correo} FOR UPDATE").ToListAsync(ct)).SingleOrDefault()
            : await db.Usuarios.SingleOrDefaultAsync(x=>x.Correo==request.Correo,ct);
        if(user is null || !BCrypt.Net.BCrypt.Verify(request.Password,user.Password))
            return Unauthorized(new {message="Las credenciales proporcionadas son incorrectas."});
        if(!user.Estado) return StatusCode(403,new {message="Tu cuenta ha sido desactivada. Contacta al administrador."});
        var dto=(await users.GetByIdAsync(user.Id))!;
        var token=await identity.Issue(user,dto,ct);
        return Ok(new LoginResponseDTO {Message="¡Bienvenido al sistema!",AccessToken=token,User=dto});
    }
    [HttpGet("me"), HttpGet("profile"), Authorize]
    public async Task<IActionResult> Me() => Ok(await users.GetByIdAsync(Subject));

    [HttpGet("destinatarios-informe"), Authorize]
    public async Task<IActionResult> ReportRecipients(string? ids, int page = 1, int size = 100, CancellationToken ct = default)
    {
        var user = await users.GetByIdAsync(Subject);
        if (user is null) return Unauthorized();
        var permissions = user.RolesPermisos.Select(x => x.NombrePermiso);
        var allowed = new[] { "acceso_historial_ventas", "acceso_pagos", "acceso_egresos", "acceso_propiedades" };
        if (!permissions.Intersect(allowed).Any()) return Forbid();
        var query = db.Usuarios.AsNoTracking().Where(x => x.Estado && x.Correo != "");
        if (ids is not null)
        {
            var selection = ids.Split(',').Select(x => int.TryParse(x, out var id) ? id : 0).Distinct().ToArray();
            if (selection.Length is < 1 or > 100 || selection.Any(x => x <= 0)) return UnprocessableEntity();
            query = query.Where(x => selection.Contains(x.Id));
        }
        page = Math.Clamp(page, 1, 1000000);
        size = Math.Clamp(size, 1, 100);
        var total = await query.CountAsync(ct);
        var data = await query.OrderBy(x => x.Nombre).ThenBy(x => x.Id).Skip((page - 1) * size).Take(size)
            .Select(x => new { id = x.Id, nombre = x.Nombre, correo = x.Correo }).ToListAsync(ct);
        return Ok(new { data, total, last_page = Math.Max(1, (int)Math.Ceiling((double)total / size)) });
    }
    [HttpPut("profile"), Authorize]
    public async Task<IActionResult> Profile(OwnProfileDTO dto,CancellationToken ct) {
        var user=await db.Usuarios.SingleAsync(x=>x.Id==Subject,ct);
        if(await db.Usuarios.AnyAsync(x=>x.Correo==dto.Correo && x.Id!=Subject,ct))
            return UnprocessableEntity(new {message="Correo ya registrado.",errors=new {correo=new[]{"El correo ya está registrado."}}});
        user.Nombre=dto.Nombre;user.Correo=dto.Correo;user.UpdatedAt=DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return Ok(new {message="Perfil actualizado correctamente",data=await users.GetByIdAsync(Subject)});
    }
    [HttpPut("password"), Authorize]
    public async Task<IActionResult> Password(OwnPasswordDTO dto,CancellationToken ct) {
        var user=await db.Usuarios.SingleAsync(x=>x.Id==Subject,ct);
        if(!BCrypt.Net.BCrypt.Verify(dto.Actual,user.Password))
            return UnprocessableEntity(new {message="Contraseña actual incorrecta.",errors=new {password_actual=new[]{"La contraseña actual no es correcta."}}});
        if(!OwnPasswordDTO.Strong(dto.Nuevo) || dto.Nuevo!=dto.Confirmation)
            return UnprocessableEntity(new {message="Verifica la contraseña nueva.",errors=new {password_nuevo=new[]{"Usa ocho caracteres, mayúscula, minúscula, número y símbolo, con confirmación."}}});
        user.Password=BCrypt.Net.BCrypt.HashPassword(dto.Nuevo);user.UpdatedAt=DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return Ok(new {message="Contraseña actualizada correctamente",reauth_required=true});
    }
    // Only signature-verified ownership is needed to revoke this exact jti. No resource access.
    [HttpPost("logout"), AllowAnonymous]
    public async Task<IActionResult> Logout(CancellationToken ct) {
        var header=Request.Headers.Authorization.ToString();
        if(!header.StartsWith("Bearer ",StringComparison.Ordinal)) return Unauthorized();
        ClaimsPrincipal principal;
        try { principal=identity.Verify(header[7..],false); }
        catch(Microsoft.IdentityModel.Tokens.SecurityTokenException) { return Unauthorized(); }
        catch(ArgumentException) { return Unauthorized(); }
        await identity.Revoke(principal,ct);
        return Ok(new {message="Sesión cerrada correctamente"});
    }
}
