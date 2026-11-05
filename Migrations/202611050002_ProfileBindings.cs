using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MSMultilider.Seguridad.Repositories;
namespace MSMultilider.Seguridad.Migrations;
[DbContext(typeof(ContextDatabase)),Migration("202611050002_ProfileBindings")]
public sealed class ProfileBindings:Migration {
    protected override void Up(MigrationBuilder m)=>m.Sql(@"CREATE TABLE profile_bindings (
Id varchar(150) NOT NULL PRIMARY KEY,UserId int NOT NULL,LastOperation varchar(36) NOT NULL,Hash varchar(64) NOT NULL);");
    protected override void Down(MigrationBuilder m)=>throw new InvalidOperationException("Los vínculos de identidad no se eliminan mediante down.");
}
