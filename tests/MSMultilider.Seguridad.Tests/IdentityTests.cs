using System.Net;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;
using Xunit;

namespace MSMultilider.Seguridad.Tests;
public sealed class ApiFactory:WebApplicationFactory<Program> {
    public const string Key="fixture-identity-test-key-never-use-in-production-0123456789-abcdef";
    private readonly SqliteConnection connection=new("Data Source=:memory:");
    public bool Seeded {get;private set;}
    protected override void ConfigureWebHost(IWebHostBuilder builder) {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_,config)=>config.AddInMemoryCollection(new Dictionary<string,string?> {
            ["Jwt:Key"]=Key,["Jwt:Issuer"]="identity-tests",["Jwt:Audience"]="identity-tests",
            ["Identity:LegacyUntil"]=DateTimeOffset.UtcNow.AddHours(8).ToString("O"),["Logging:LogLevel:Default"]="Error"
        }));
        builder.ConfigureServices(services=> {
            connection.Open();
            services.RemoveAll<DbContextOptions<ContextDatabase>>();
            services.AddDbContext<ContextDatabase>(o=>o.UseSqlite(connection));
        });
    }
    public HttpClient Client() {
        var client=CreateClient();
        if(!Seeded) {
            using var scope=Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<ContextDatabase>();
            db.Database.EnsureCreated();
            var user=new Usuario {Nombre="Operador ficticio",Correo="operator@example.test",Password=BCrypt.Net.BCrypt.HashPassword("Test-only-Password-42!",4)};
            var other=new Usuario {Nombre="Otro usuario",Correo="other@example.test",Password=user.Password};
            db.AddRange(user,other);db.SaveChangesAsync().GetAwaiter().GetResult();
            var role=new Rol {Nombre="Operador"};db.Add(role);db.SaveChangesAsync().GetAwaiter().GetResult();
            foreach(var permission in new[]{"acceso_usuarios","acceso_roles","acceso_permisos","acceso_propiedades"}) {
                var perm=new Permiso {Nombre=permission};var link=new RolPermiso {Rol=role,Permiso=perm};
                db.Add(new RolPermisoUsuario {Usuario=user,RolPermiso=link});
            }
            db.SaveChangesAsync().GetAwaiter().GetResult();
            // Version zero represents the existing pre-F3 records for bounded legacy tests.
            user.AuthVersion=0;db.SaveChangesAsync().GetAwaiter().GetResult();Seeded=true;
        }
        return client;
    }
    public async Task<string> Login(HttpClient client,string email="operator@example.test") {
        var response=await client.PostAsJsonAsync("/api/auth/login",new {correo=email,password="Test-only-Password-42!"});
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var json=await response.Content.ReadFromJsonAsync<JsonElement>();return json.GetProperty("accessToken").GetString()!;
    }
    public static string Token(string? issuer="identity-tests", string? audience="identity-tests",string? sub="1",bool version=true,
        bool expired=false,string? algorithm=null,string? key=null, bool jti=true) {
        var now=DateTime.UtcNow;var claims=new List<Claim>();
        if(sub is not null) claims.Add(new("sub",sub));
        if(jti) claims.Add(new("jti",Guid.NewGuid().ToString()));
        if(version) {claims.Add(new("ver","0",ClaimValueTypes.Integer64));claims.Add(new("iat",new DateTimeOffset(now.AddMinutes(-5)).ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64));}
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(issuer,audience,claims,now.AddMinutes(-5),now.AddMinutes(expired?-2:15),
            new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key??Key)),algorithm??SecurityAlgorithms.HmacSha256)));
    }
    public async Task Mutate(Func<ContextDatabase,Task> action) {using var scope=Services.CreateScope();await action(scope.ServiceProvider.GetRequiredService<ContextDatabase>());}
    protected override void Dispose(bool disposing) {base.Dispose(disposing);if(disposing)connection.Dispose();}
}

public sealed class IdentityTests {
    [Fact] public async Task LoginMeAndProfileUseStableSubject() {
        using var api=new ApiFactory();using var client=api.Client();var token=await api.Login(client);
        client.DefaultRequestHeaders.Authorization=new("Bearer",token);
        var me=await client.GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.Equal(1,me.GetProperty("id").GetInt32());Assert.Equal(4,me.GetProperty("rolesPermisos").GetArrayLength());
        Assert.Equal(HttpStatusCode.OK,(await client.PutAsJsonAsync("/api/auth/profile",new {nombre="Nuevo nombre",correo="renamed@example.test"})).StatusCode);
        me=await client.GetFromJsonAsync<JsonElement>("/api/auth/me");Assert.Equal(1,me.GetProperty("id").GetInt32());Assert.Equal("renamed@example.test",me.GetProperty("correo").GetString());
    }
    [Fact] public async Task LogoutIsRealIdempotentAndSpecificToDevice() {
        using var api=new ApiFactory();using var client=api.Client();var first=await api.Login(client);var second=await api.Login(client);
        client.DefaultRequestHeaders.Authorization=new("Bearer",first);
        Assert.Equal(HttpStatusCode.OK,(await client.PostAsync("/api/auth/logout",null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK,(await client.PostAsync("/api/auth/logout",null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/api/auth/me")).StatusCode);
        client.DefaultRequestHeaders.Authorization=new("Bearer",second);Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/api/auth/me")).StatusCode);
    }
    [Fact] public async Task PasswordRevokesAllSessionsAndKeepsOtherUser() {
        using var api=new ApiFactory();using var client=api.Client();var first=await api.Login(client);var second=await api.Login(client);var other=await api.Login(client,"other@example.test");
        client.DefaultRequestHeaders.Authorization=new("Bearer",first);
        Assert.Equal(HttpStatusCode.OK,(await client.PutAsJsonAsync("/api/auth/password",new {password_actual="Test-only-Password-42!",password_nuevo="New-test-Password-43!",password_nuevo_confirmation="New-test-Password-43!"})).StatusCode);
        foreach(var token in new[]{first,second}) {client.DefaultRequestHeaders.Authorization=new("Bearer",token);Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/api/auth/me")).StatusCode);}
        client.DefaultRequestHeaders.Authorization=new("Bearer",other);Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/api/auth/me")).StatusCode);
    }
    [Theory, InlineData(false),InlineData(true)] public async Task StateAndSharedPermissionChangesInvalidateOldTokens(bool changePermission) {
        using var api=new ApiFactory();using var client=api.Client();var token=await api.Login(client);
        await api.Mutate(async db=>{if(changePermission)(await db.Permisos.FirstAsync()).Nombre="changed";else(await db.Usuarios.FindAsync(1))!.Estado=false;await db.SaveChangesAsync();});
        client.DefaultRequestHeaders.Authorization=new("Bearer",token);Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/api/auth/me")).StatusCode);
    }
    [Fact] public async Task SelfProfileRejectsPrivilegeEscalationAndDuplicateEmail() {
        using var api=new ApiFactory();using var client=api.Client();client.DefaultRequestHeaders.Authorization=new("Bearer",await api.Login(client,"other@example.test"));
        Assert.Equal(HttpStatusCode.BadRequest,(await client.PutAsJsonAsync("/api/auth/profile",new {nombre="Other",correo="other@example.test",id=1,estado=true})).StatusCode);
        Assert.Equal(HttpStatusCode.UnprocessableEntity,(await client.PutAsJsonAsync("/api/auth/profile",new {nombre="Other",correo="operator@example.test"})).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,(await client.GetAsync("/api/usuario")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,(await client.PutAsJsonAsync("/api/usuario/1",new {password="Changed-Password-42!"})).StatusCode);
    }
    [Theory, InlineData("issuer"),InlineData("audience"),InlineData("key"),InlineData("sub"),InlineData("jti"),InlineData("expired"),InlineData("algorithm")]
    public async Task InvalidCryptographicCredentialsRejected(string invalid) {
        using var api=new ApiFactory();using var client=api.Client();
        var valid=await api.Login(client);
        client.DefaultRequestHeaders.Authorization=new("Bearer",valid);
        Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/api/auth/me")).StatusCode);
        var payload=new JwtSecurityTokenHandler().ReadJwtToken(valid).Payload;
        if(invalid=="issuer")payload["iss"]="foreign";
        if(invalid=="audience")payload["aud"]="foreign";
        if(invalid=="sub")payload.Remove("sub");
        if(invalid=="jti")payload.Remove("jti");
        if(invalid=="expired")payload["exp"]=DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds();
        var creds=new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(invalid=="key"?new string('X',64):ApiFactory.Key)),invalid=="algorithm"?SecurityAlgorithms.HmacSha512:SecurityAlgorithms.HmacSha256);
        var token=new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(new JwtHeader(creds),payload));
        client.DefaultRequestHeaders.Authorization=new("Bearer",token);Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/api/auth/me")).StatusCode);
    }
    [Fact] public async Task BoundedLegacyCredentialCanBeRevoked() {
        using var api=new ApiFactory();using var client=api.Client();client.DefaultRequestHeaders.Authorization=new("Bearer",ApiFactory.Token(version:false));
        Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK,(await client.PostAsync("/api/auth/logout",null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.GetAsync("/api/auth/me")).StatusCode);
    }
    [Fact] public async Task RoleSyncPreservesRetainedAssignments() {
        using var api=new ApiFactory();using var client=api.Client();client.DefaultRequestHeaders.Authorization=new("Bearer",await api.Login(client));
        Assert.Equal(HttpStatusCode.OK,(await client.PostAsJsonAsync("/api/rol/1/permisos/sync",new {permisos=new[]{1,2,3,4}})).StatusCode);
        var me=await client.GetFromJsonAsync<JsonElement>("/api/auth/me");Assert.Equal(4,me.GetProperty("rolesPermisos").GetArrayLength());
    }
    [Fact] public async Task InvalidLoginAndWeakPasswordDoNotMutate() {
        using var api=new ApiFactory();using var client=api.Client();
        Assert.Equal(HttpStatusCode.Unauthorized,(await client.PostAsJsonAsync("/api/auth/login",new {correo="operator@example.test",password="wrong"})).StatusCode);
        client.DefaultRequestHeaders.Authorization=new("Bearer",await api.Login(client));
        Assert.Equal(HttpStatusCode.UnprocessableEntity,(await client.PutAsJsonAsync("/api/auth/password",new {password_actual="Test-only-Password-42!",password_nuevo="weak",password_nuevo_confirmation="weak"})).StatusCode);
        Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/api/auth/me")).StatusCode);
    }
    [Fact] public async Task UserManagementCanReadButCannotCreateRoleCombinations() {
        using var api=new ApiFactory();using var client=api.Client();
        await api.Mutate(async db=>{db.RolPermisoUsuarios.Add(new RolPermisoUsuario {UserId=2,RolPermisoId=1});await db.SaveChangesAsync();});
        client.DefaultRequestHeaders.Authorization=new("Bearer",await api.Login(client,"other@example.test"));
        Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/api/rolpermiso")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,(await client.PostAsJsonAsync("/api/rolpermiso",new {rolId=1,permisoId=1})).StatusCode);
    }
    [Fact] public async Task MissingAssignmentSetCannotClearExistingPermissions() {
        using var api=new ApiFactory();using var client=api.Client();client.DefaultRequestHeaders.Authorization=new("Bearer",await api.Login(client));
        Assert.Equal(HttpStatusCode.BadRequest,(await client.PostAsJsonAsync("/api/usuario/1/asignaciones",new {})).StatusCode);
        var me=await client.GetFromJsonAsync<JsonElement>("/api/auth/me");Assert.Equal(4,me.GetProperty("rolesPermisos").GetArrayLength());
    }
}
