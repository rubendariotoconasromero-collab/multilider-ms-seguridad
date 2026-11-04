using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;

namespace MSMultilider.Seguridad.Services;

public sealed class IdentityProtocol(ContextDatabase db, IConfiguration config) {
    public static TokenValidationParameters Parameters(IConfiguration config, bool lifetime=true) => new() {
        ValidateIssuer=true, ValidateAudience=true, ValidateIssuerSigningKey=true, ValidateLifetime=lifetime,
        RequireExpirationTime=true, RequireSignedTokens=true, ValidAlgorithms=[SecurityAlgorithms.HmacSha256],
        ValidIssuer=config["Jwt:Issuer"], ValidAudience=config["Jwt:Audience"],
        IssuerSigningKeyResolver=(_,_,_,_) => {
            var key=config["Jwt:Key"];
            return !string.IsNullOrWhiteSpace(key) && Encoding.UTF8.GetByteCount(key)>=32
                ? [new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))] : [];
        },
        ClockSkew=TimeSpan.FromSeconds(30), NameClaimType="sub"
    };

    public ClaimsPrincipal Verify(string token, bool lifetime=true) {
        var handler=new JwtSecurityTokenHandler { MapInboundClaims=false };
        var principal=handler.ValidateToken(token,Parameters(config,lifetime),out var validated);
        var jwt=(JwtSecurityToken)validated;
        if(!int.TryParse(principal.FindFirstValue("sub"),out var id) || id<=0 ||
            !Guid.TryParse(principal.FindFirstValue("jti"),out _) || !jwt.Payload.ContainsKey("exp"))
            throw new SecurityTokenValidationException("Invalid identity.");
        if(principal.HasClaim(x=>x.Type=="ver")) {
            if(!long.TryParse(principal.FindFirstValue("ver"),out var version) || version<0 ||
                !long.TryParse(principal.FindFirstValue("iat"),out var issued) || !jwt.Payload.ContainsKey("nbf") || issued>DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds())
                throw new SecurityTokenValidationException("Invalid claims.");
        } else if(!DateTimeOffset.TryParse(config["Identity:LegacyUntil"],out var until) ||
            DateTimeOffset.UtcNow>until.AddSeconds(30) || jwt.ValidTo>until.UtcDateTime)
            throw new SecurityTokenValidationException("Legacy credential expired.");
        // A logout may accept an expired credential, but never one not valid yet.
        if(!lifetime && jwt.Payload.ContainsKey("nbf") && jwt.ValidFrom>DateTime.UtcNow.AddSeconds(30))
            throw new SecurityTokenValidationException("Not valid yet.");
        return principal;
    }

    public async Task<bool> IsActive(ClaimsPrincipal principal, CancellationToken ct) {
        var id=int.Parse(principal.FindFirstValue("sub")!);
        var version=long.Parse(principal.FindFirstValue("ver") ?? "0");
        var user=await db.Usuarios.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        if(user is null || !user.Estado || user.AuthVersion!=version) return false;
        var jti=principal.FindFirstValue("jti")!;
        var session=await db.AuthSessions.AsNoTracking().SingleOrDefaultAsync(x=>x.Jti==jti,ct);
        // Only bounded legacy credentials may lack a persisted session.
        return session is null ? !principal.HasClaim(x=>x.Type=="ver") :
            session.UserId==id && session.Version==version && session.RevokedAt is null && session.ExpiresAt>DateTime.UtcNow.AddSeconds(-30);
    }

    public async Task<string> Issue(Usuario user, DTOs.UsuarioDTO dto, CancellationToken ct) {
        var now=DateTime.UtcNow;
        var jti=Guid.NewGuid().ToString();
        var claims=new List<Claim> { new("sub",user.Id.ToString()),new("email",user.Correo),new("name",user.Nombre),
            new("jti",jti),new("ver",user.AuthVersion.ToString(),ClaimValueTypes.Integer64),
            new("iat",new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64) };
        claims.AddRange(dto.RolesPermisos.Select(x=>x.NombrePermiso).Distinct().Select(x=>new Claim("permission",x)));
        var expires=now.AddHours(8);
        db.AuthSessions.Add(new AuthSession {Jti=jti,UserId=user.Id,Version=user.AuthVersion,ExpiresAt=expires});
        await db.SaveChangesAsync(ct);
        var key=config["Jwt:Key"] ?? "";
        if(Encoding.UTF8.GetByteCount(key)<32) throw new InvalidOperationException("Configure a strong Jwt:Key.");
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(config["Jwt:Issuer"],config["Jwt:Audience"],
            claims,now,expires,new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),SecurityAlgorithms.HmacSha256)));
    }

    public async Task Revoke(ClaimsPrincipal principal, CancellationToken ct) {
        var jti=principal.FindFirstValue("jti")!;
        var session=await db.AuthSessions.FindAsync([jti],ct);
        if(session is null) {
            var exp=long.Parse(principal.FindFirstValue("exp")!);
            db.AuthSessions.Add(new AuthSession {Jti=jti,UserId=int.Parse(principal.FindFirstValue("sub")!),
                Version=long.Parse(principal.FindFirstValue("ver") ?? "0"),ExpiresAt=DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime,RevokedAt=DateTime.UtcNow});
        } else {
            if(session.UserId!=int.Parse(principal.FindFirstValue("sub")!)) throw new SecurityTokenValidationException("Invalid session owner.");
            session.RevokedAt=DateTime.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }
}
