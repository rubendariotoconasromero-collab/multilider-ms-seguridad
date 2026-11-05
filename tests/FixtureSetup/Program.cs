using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MySqlConnector;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;
using MSMultilider.Seguridad.Services;
using MSMultilider.Seguridad.DTOs;
if(Environment.GetEnvironmentVariable("MULTILIDER_TEST_ISOLATED")!="1") throw new InvalidOperationException("Isolated runner required.");
var connection=new MySqlConnectionStringBuilder(Environment.GetEnvironmentVariable("ConnectionStrings__MySQL") ?? throw new InvalidOperationException("Test connection required."));
if(connection.Server!="127.0.0.1" || connection.Port.ToString()!=Environment.GetEnvironmentVariable("MULTILIDER_TEST_PORT") || connection.UserID!="identity_test")
    throw new InvalidOperationException("Unsafe SQL connection.");
connection.Database="multilider_identity_fresh_tests_isolated";
await using var db=new ContextDatabase(new DbContextOptionsBuilder<ContextDatabase>().UseMySql(connection.ConnectionString,new MySqlServerVersion(new Version(8,0,0))).Options);
// Characterize the reversible F3 baseline before applying F5's deliberately durable decisions.
var phase3=db.Database.GetMigrations().Single(id=>id.EndsWith("_IdentitySessions",StringComparison.Ordinal));
await db.GetService<IMigrator>().MigrateAsync(db.GetService<IMigrationsIdGenerator>().GetName(phase3));
var hash=BCrypt.Net.BCrypt.HashPassword("Recovery-test-Password-42!",4);
var user=new Usuario {Nombre="Recovery fixture",Correo="recovery@example.test",Password=hash};db.Add(user);await db.SaveChangesAsync();
var userId=user.Id;
await db.GetService<IMigrator>().MigrateAsync("0");
var count=await db.Database.SqlQueryRaw<int>("SELECT COUNT(*) AS Value FROM users").SingleAsync();
if(count!=1) throw new InvalidOperationException("Rollback destroyed the legacy identity.");
await db.Database.MigrateAsync();db.ChangeTracker.Clear();
user=await db.Usuarios.SingleAsync();if(user.Id!=userId || user.Password!=hash) throw new InvalidOperationException("Reapplying migration changed existing data.");
IConfiguration Config(string key)=>new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
    ["Jwt:Key"]=key,["Jwt:Issuer"]="recovery-fixture",["Jwt:Audience"]="recovery-fixture"
}).Build();
var oldKey=Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
var oldToken=await new IdentityProtocol(db,Config(oldKey)).Issue(user,new UsuarioDTO {Id=user.Id,Nombre=user.Nombre,Correo=user.Correo,Estado=true},default);
var snapshot=JsonSerializer.Serialize(new {User=new {user.Id,user.Nombre,user.Correo,user.Password,user.Estado,user.AuthVersion},Sessions=await db.AuthSessions.AsNoTracking().ToListAsync()});
var snapshotPath=Path.Combine(AppContext.BaseDirectory,"recovery-snapshot.json");
await File.WriteAllTextAsync(snapshotPath,snapshot);
using var json=JsonDocument.Parse(await File.ReadAllTextAsync(snapshotPath));
// Simulate loss/restoration only in this exclusive synthetic database.
db.AuthSessions.RemoveRange(db.AuthSessions);await db.SaveChangesAsync();
foreach(var row in json.RootElement.GetProperty("Sessions").EnumerateArray()) db.AuthSessions.Add(row.Deserialize<AuthSession>()!);
await db.SaveChangesAsync();
if(!await new IdentityProtocol(db,Config(oldKey)).IsActive(new IdentityProtocol(db,Config(oldKey)).Verify(oldToken),default))
    throw new InvalidOperationException("Snapshot did not restore session data.");
var newKey=Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
try { new IdentityProtocol(db,Config(newKey)).Verify(oldToken);throw new InvalidOperationException("Restored credential revived after recovery key rotation."); }
catch(SecurityTokenException) { }
if((await db.Usuarios.SingleAsync()).Password!=hash) throw new InvalidOperationException("Recovery changed password hash.");
Console.WriteLine("Fresh MySQL schema, additive rollback, synthetic snapshot restoration and credential invalidation passed.");
