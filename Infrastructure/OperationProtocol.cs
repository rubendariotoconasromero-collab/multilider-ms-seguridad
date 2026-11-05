using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace Multilider.Operations;

// This protocol is deliberately identical in the four independently versioned services.
public sealed record OperationAdmission(
    [property:System.Text.Json.Serialization.JsonPropertyName("operation_id")]Guid OperationId,string Kind,
    [property:System.Text.Json.Serialization.JsonPropertyName("resource_id")]int ResourceId,
    [property:System.Text.Json.Serialization.JsonPropertyName("payload_hash")]string PayloadHash,
    [property:System.Text.Json.Serialization.JsonPropertyName("parent_operation_id")]Guid? ParentOperationId=null);
public sealed record OperationAuthorization(Guid OperationId,string Kind,int ResourceId,string PayloadHash,
    string ActorIssuer,string ActorSubject,string State,Guid? ParentOperationId=null,string? OwnerIssuer=null,string? OwnerSubject=null,string Dataset="");
public sealed record OperationCheck([property:System.Text.Json.Serialization.JsonPropertyName("operation_id")]Guid OperationId,string Action);
public sealed record OperationDecision([property:System.Text.Json.Serialization.JsonPropertyName("operation_id")]Guid OperationId,string Decision);
public sealed class ProtocolException(string message,int status=503):Exception(message) { public int Status{get;}=status; }
public static class OperationProtocol {
    public static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web) {PropertyNamingPolicy=JsonNamingPolicy.SnakeCaseLower,PropertyNameCaseInsensitive=true,NumberHandling=System.Text.Json.Serialization.JsonNumberHandling.AllowReadingFromString};
    public static string Hash<T>(T value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(JsonSerializer.SerializeToElement(value,Json)))));
    public static string Canonical(JsonElement e)=>e.ValueKind switch {
        JsonValueKind.Object=>"{"+string.Join(",",e.EnumerateObject().OrderBy(p=>p.Name,StringComparer.Ordinal).Select(p=>JsonSerializer.Serialize(p.Name)+":"+Canonical(p.Value)))+"}",
        JsonValueKind.Array=>"["+string.Join(",",e.EnumerateArray().Select(Canonical))+"]",
        JsonValueKind.Number when e.TryGetDecimal(out var number)=>number.ToString("G29",System.Globalization.CultureInfo.InvariantCulture),
        _=>e.GetRawText()
    };
    public static Guid Command(Guid operation,string step) {
        var bytes=SHA256.HashData(Encoding.UTF8.GetBytes(operation.ToString("D")+"|"+step));
        return new Guid(bytes.AsSpan(0,16));
    }
    public static ClaimsPrincipal Principal(OperationAuthorization a)=>new(new ClaimsIdentity(new[]{
        new Claim("iss",a.OwnerIssuer??a.ActorIssuer),new Claim("sub",a.OwnerSubject??a.ActorSubject),
        new Claim("permission","acceso_ventas")},"Operation"));
    public static bool Pin(X509Certificate2 cert,string? value,bool client) {
        var now=DateTime.UtcNow;
        return cert.NotBefore.ToUniversalTime()<=now && cert.NotAfter.ToUniversalTime()>now &&
            (value??"").Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)
                .Any(p=>string.Equals(p.Replace(":",""),cert.GetCertHashString(HashAlgorithmName.SHA256),StringComparison.OrdinalIgnoreCase)) &&
            cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e=>e.EnhancedKeyUsages.Cast<Oid>().Any(o=>o.Value==(client?"1.3.6.1.5.5.7.3.2":"1.3.6.1.5.5.7.3.1")));
    }
    public static async Task<string> Caller(HttpContext context,IConfiguration config,string? expected=null) {
        var cert=await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        if(!context.Request.IsHttps || cert is null)throw new ProtocolException("Canal interno no autorizado.",403);
        var services=new[]{"comercial","finanzas","propiedades","seguridad","backend"};
        var matches=services.Where(s=>Pin(cert,config[$"Operations:Callers:{s}:CertificateSha256"],true)).ToArray();
        if(matches.Length!=1 || expected is not null && matches[0]!=expected)throw new ProtocolException("Identidad de servicio no autorizada.",403);
        return matches[0];
    }
    public static void ConfigureTls(Microsoft.AspNetCore.Hosting.WebHostBuilderContext _,Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions options,IConfiguration config) {
        var path=config["Operations:ServerCertificatePath"];
        if(string.IsNullOrWhiteSpace(path))return;
#pragma warning disable SYSLIB0057
        var cert=new X509Certificate2(path,config["Operations:ServerCertificatePassword"],OperatingSystem.IsWindows()?X509KeyStorageFlags.DefaultKeySet:X509KeyStorageFlags.EphemeralKeySet);
#pragma warning restore SYSLIB0057
        options.ConfigureHttpsDefaults(o=>{
            o.ServerCertificate=cert;o.ClientCertificateMode=Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
            o.ClientCertificateValidation=(c,_,_)=>new[]{"comercial","finanzas","propiedades","seguridad","backend"}.Any(s=>Pin(c,config[$"Operations:Callers:{s}:CertificateSha256"],true));
        });
    }
    public static void RequireMigrationTarget(DbContext db,IConfiguration config) {
        var expected=config["Migrations:DatabaseName"];
        var actual=db.Database.GetDbConnection().Database;
        if(string.IsNullOrWhiteSpace(expected)||!string.Equals(expected,actual,StringComparison.Ordinal)||
            new[]{"master","model","msdb","tempdb","mysql","information_schema","sys","performance_schema"}.Contains(actual,StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Explicit matching authority database is required.");
    }
    public static async Task PrintPreflight(DbContext db,IConfiguration config,string service,CancellationToken ct=default) {
        RequireMigrationTarget(db,config);
        if(!await db.Database.CanConnectAsync(ct))throw new InvalidOperationException("The explicitly selected database is not available.");
        var known=db.Database.GetMigrations().ToArray();var applied=(await db.Database.GetAppliedMigrationsAsync(ct)).ToArray();
        if(applied.Except(known).Any())throw new InvalidOperationException("Unknown migration history; stop and inspect the backup.");
        Console.WriteLine(JsonSerializer.Serialize(new{service,database=db.Database.GetDbConnection().Database,dataset=config["Operations:Dataset"],applied,pending=known.Except(applied)},Json));
    }
    public static async Task Lock(DbContext db,string key,CancellationToken ct) {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Operation lock requires transaction.");
        if(db.Database.ProviderName?.Contains("SqlServer")==true)
            await db.Database.ExecuteSqlInterpolatedAsync($"DECLARE @r int; EXEC @r=sys.sp_getapplock @Resource={key},@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000; IF @r<0 THROW 51000,'Operation lock timeout',1;",ct);
    }
}
public class OperationChannel(IConfiguration config,ILogger<OperationChannel>? log=null) {
    public virtual async Task<JsonElement> Send(string service,HttpMethod method,string path,object? body,CancellationToken ct,string? bearer=null) {
        if(path.StartsWith("/") || path.Contains("..") || path.Contains('?') || !new[]{"seguridad","propiedades","finanzas","comercial"}.Contains(service))
            throw new InvalidOperationException("Untrusted internal route.");
        var url=config[$"Operations:Peers:{service}:Url"];
        if(!Uri.TryCreate(url,UriKind.Absolute,out var uri)||uri.Scheme!="https"||!string.IsNullOrEmpty(uri.UserInfo)||!string.IsNullOrEmpty(uri.Query)||!string.IsNullOrEmpty(uri.Fragment))
            throw new ProtocolException("INTEGRATION_NOT_READY: falta canal HTTPS de operaciones.");
        var certificate=config["Operations:ClientCertificatePath"];
        var pins=config[$"Operations:Peers:{service}:ServerCertificateSha256"];
        if(string.IsNullOrWhiteSpace(certificate)||string.IsNullOrWhiteSpace(pins))throw new ProtocolException("INTEGRATION_NOT_READY: falta identidad TLS de operaciones.");
#pragma warning disable SYSLIB0057
        using var cert=new X509Certificate2(certificate,config["Operations:ClientCertificatePassword"],OperatingSystem.IsWindows()?X509KeyStorageFlags.DefaultKeySet:X509KeyStorageFlags.EphemeralKeySet);
#pragma warning restore SYSLIB0057
        using var handler=new SocketsHttpHandler{AllowAutoRedirect=false,ConnectTimeout=TimeSpan.FromSeconds(2)};
        handler.SslOptions.ClientCertificates=new X509CertificateCollection{cert};
        handler.SslOptions.RemoteCertificateValidationCallback=(_,c,_,errors)=>c is X509Certificate2 remote &&
            (errors&SslPolicyErrors.RemoteCertificateNameMismatch)==0 && OperationProtocol.Pin(remote,pins,false);
        using var client=new HttpClient(handler){BaseAddress=new Uri(url.TrimEnd('/')+"/"),Timeout=TimeSpan.FromSeconds(5)};
        using var request=new HttpRequestMessage(method,path);
        if(bearer is not null)request.Headers.Authorization=AuthenticationHeaderValue.Parse(bearer);
        if(body is not null)request.Content=new StringContent(JsonSerializer.Serialize(body,OperationProtocol.Json),Encoding.UTF8,"application/json");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
        if(!response.IsSuccessStatusCode) {
            log?.LogWarning("Internal operation rejected: {Service} {Path} {Status}",service,path,(int)response.StatusCode);
            throw new ProtocolException("El servicio no permite completar este paso.",(int)response.StatusCode);
        }
        // Read with a hard bound; do not buffer an untrusted unbounded response.
        await using var stream=await response.Content.ReadAsStreamAsync(deadline.Token);
        using var memory=new MemoryStream();var buffer=new byte[8192];int n;
        while((n=await stream.ReadAsync(buffer,deadline.Token))>0) {if(memory.Length+n>2*1024*1024)throw new ProtocolException("Respuesta interna demasiado grande.");memory.Write(buffer,0,n);}
        try{return JsonSerializer.Deserialize<JsonElement>(memory.ToArray(),OperationProtocol.Json);}
        catch(JsonException){throw new ProtocolException("Contrato interno inválido.");}
    }
    public async Task<OperationAuthorization> Authorize(HttpContext context,Guid operation,string action,IConfiguration configuration,string expectedCaller="comercial") {
        await OperationProtocol.Caller(context,configuration,expectedCaller);
        return await Check(operation,action,context.RequestAborted);
    }
    public virtual async Task<OperationAuthorization> Check(Guid operation,string action,CancellationToken ct) {
        var json=await Send("seguridad",HttpMethod.Post,"internal/operations/v1/authorize",new OperationCheck(operation,action),ct);
        var grant=json.Deserialize<OperationAuthorization>(OperationProtocol.Json)??throw new ProtocolException("Autorización inválida.");
        if(grant.OperationId!=operation||grant.Dataset!=config["Operations:Dataset"])throw new ProtocolException("Instalación de operación incompatible.",403);
        return grant;
    }
}
public sealed class OperationProtocolMiddleware(RequestDelegate next) {
    public async Task Invoke(HttpContext context) {
        try{await next(context);}catch(ProtocolException e) {
            if(context.Response.HasStarted)throw;
            context.Response.StatusCode=e.Status;
            await context.Response.WriteAsJsonAsync(new {message=e.Message,code=e.Status==503?"INTEGRATION_NOT_READY":"OPERATION_REJECTED"});
        }
    }
}
