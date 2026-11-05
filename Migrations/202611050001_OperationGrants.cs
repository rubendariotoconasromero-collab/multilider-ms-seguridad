using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MSMultilider.Seguridad.Repositories;
namespace MSMultilider.Seguridad.Migrations;
[DbContext(typeof(ContextDatabase)),Migration("202611050001_OperationGrants")]
public sealed class OperationGrants:Migration {
    protected override void Up(MigrationBuilder m)=>m.Sql(@"CREATE TABLE operation_grants (
Id varchar(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
ParentId varchar(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
Kind varchar(32) NOT NULL,ResourceId int NOT NULL,PayloadHash varchar(64) NOT NULL,
Dataset varchar(100) NOT NULL,UserId int NOT NULL,UserVersion bigint NOT NULL,SessionJti varchar(36) NOT NULL,
State varchar(32) NOT NULL,CreatedAt datetime(6) NOT NULL,UpdatedAt datetime(6) NOT NULL,
INDEX ix_operations_user(UserId),INDEX ix_operations_parent(ParentId));");
    protected override void Down(MigrationBuilder m)=>throw new InvalidOperationException("Los grants con decisiones durables requieren recuperación compatible; no down destructivo.");
}
