using Multilider.Operations;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MSMultilider.Seguridad.Repositories;
using MSMultilider.Seguridad.Services;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Base de datos MySQL
var connectionString = builder.Configuration.GetConnectionString("MySQL");
builder.Services.AddDbContext<ContextDatabase>(opt =>
    opt.UseMySql(connectionString, new MySqlServerVersion(new Version(8,0,0)), o=>o.CommandTimeout(5)));

// Inyección de dependencias
builder.Services.AddScoped<IUsuarioService, UsuarioService>();
builder.Services.AddScoped<IRolService, RolService>();
builder.Services.AddScoped<IPermisoService, PermisoService>();
builder.Services.AddScoped<IRolPermisoService, RolPermisoService>();

builder.Services.AddScoped<IdentityProtocol>();

// JWT Authentication
var jwtKey = builder.Configuration["Jwt:Key"]!;
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.IncludeErrorDetails = false;
        options.TokenValidationParameters = IdentityProtocol.Parameters(builder.Configuration);
        options.Events = new JwtBearerEvents {
            OnTokenValidated = async context => {
                try {
                    var protocol=context.HttpContext.RequestServices.GetRequiredService<IdentityProtocol>();
                    var raw=context.Request.Headers.Authorization.ToString();
                    var principal=protocol.Verify(raw.StartsWith("Bearer ") ? raw[7..] : "");
                    if(!await protocol.IsActive(principal,context.HttpContext.RequestAborted)) context.Fail("Session inactive.");
                    else {
                        var dto=await context.HttpContext.RequestServices.GetRequiredService<IUsuarioService>().GetByIdAsync(int.Parse(principal.FindFirst("sub")!.Value));
                        var current=(System.Security.Claims.ClaimsIdentity)principal.Identity!;
                        foreach(var claim in current.FindAll("permission").ToArray()) current.RemoveClaim(claim);
                        foreach(var name in dto!.RolesPermisos.Select(x=>x.NombrePermiso).Distinct()) current.AddClaim(new System.Security.Claims.Claim("permission",name));
                        context.Principal=principal;
                    }
                } catch(Microsoft.IdentityModel.Tokens.SecurityTokenException) { context.Fail("Invalid credential."); }
                catch(ArgumentException) { context.Fail("Invalid credential."); }
            }
        };
    });

builder.Services.AddAuthorization(o => {
    o.AddPolicy("assignment_catalog",p=>p.RequireAuthenticatedUser().RequireAssertion(c=>c.User.HasClaim("permission","acceso_roles") || c.User.HasClaim("permission","acceso_usuarios")));
    foreach(var permission in new[]{"acceso_usuarios","acceso_roles","acceso_permisos"})
        o.AddPolicy(permission,p=>p.RequireAuthenticatedUser().RequireClaim("permission",permission));
});
builder.Services.AddRateLimiter(o=> {
    o.RejectionStatusCode=429;
    o.AddPolicy("login",context=>RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",_=>new FixedWindowRateLimiterOptions {
            PermitLimit=builder.Configuration.GetValue<int>("Identity:LoginPermitLimit",20),Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true }));
});

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
        policy.WithOrigins(builder.Configuration["Cors:AllowedOrigin"] ?? "http://localhost:5173")
              .AllowAnyHeader()
              .AllowAnyMethod());
});

builder.Services.AddControllers();

// Swagger con soporte JWT
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "MSMultilider.Seguridad", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header. Ejemplo: 'Bearer {token}'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddSingleton<OperationChannel>();
builder.WebHost.ConfigureKestrel((context,options)=>OperationProtocol.ConfigureTls(context,options,builder.Configuration));
var app = builder.Build();
if(args.Contains("--preflight-f5")) {
    await using var scope=app.Services.CreateAsyncScope();
    await OperationProtocol.PrintPreflight(scope.ServiceProvider.GetRequiredService<ContextDatabase>(),builder.Configuration,"seguridad");
    return;
}

// Explicit operator command only. Never migrate or seed when starting the HTTP service.
if(args.Contains("--migrate-identity")) {
    await using var scope=app.Services.CreateAsyncScope();
    var db=scope.ServiceProvider.GetRequiredService<ContextDatabase>();
    if(!string.IsNullOrWhiteSpace(builder.Configuration["Operations:Dataset"]))await OperationProtocol.PrintPreflight(db,builder.Configuration,"seguridad");
    await db.Database.MigrateAsync();
    return;
}
if(string.IsNullOrWhiteSpace(builder.Configuration["Jwt:Issuer"]) || string.IsNullOrWhiteSpace(builder.Configuration["Jwt:Audience"]) ||
    Encoding.UTF8.GetByteCount(builder.Configuration["Jwt:Key"] ?? "")<32) throw new InvalidOperationException("Configure Jwt:Issuer, Jwt:Audience and a Jwt:Key of at least 32 bytes.");
app.Use(async(context,next)=> {
    try { await next(); }
    catch(ProtocolException e) { context.Response.StatusCode=e.Status;await context.Response.WriteAsJsonAsync(new {message=e.Message}); }
    catch(KeyNotFoundException) { context.Response.StatusCode=404;await context.Response.WriteAsJsonAsync(new {message="Recurso no encontrado."}); }
    catch(ArgumentException) { context.Response.StatusCode=422;await context.Response.WriteAsJsonAsync(new {message="Datos no válidos."}); }
    catch(DbUpdateConcurrencyException) { context.Response.StatusCode=409;await context.Response.WriteAsJsonAsync(new {message="Conflicto; vuelve a consultar el estado."}); }
    catch(DbUpdateException) { context.Response.StatusCode=422;await context.Response.WriteAsJsonAsync(new {message="Datos duplicados o referencias no válidas."}); }
    catch(Exception e) { context.RequestServices.GetRequiredService<ILogger<Program>>().LogError("Security operation failed: {FailureType}",e.GetType().FullName); context.Response.StatusCode=503;await context.Response.WriteAsJsonAsync(new {message="Seguridad no está disponible."}); }
});

app.UseSwagger();
app.UseSwaggerUI();

app.UseCors("AllowFrontend");
app.UseRateLimiter();
app.UseMiddleware<AuthorityMutationMiddleware>();
app.UseMiddleware<OperationProtocolMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program { }
