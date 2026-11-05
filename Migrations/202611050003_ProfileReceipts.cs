using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MSMultilider.Seguridad.Repositories;
namespace MSMultilider.Seguridad.Migrations;
[DbContext(typeof(ContextDatabase)),Migration("202611050003_ProfileReceipts")]
public sealed class ProfileReceipts:Migration {
    protected override void Up(MigrationBuilder m) {
        m.Sql("ALTER TABLE profile_bindings ADD COLUMN ActivationVersion bigint NOT NULL DEFAULT 0;");
        m.Sql("CREATE TABLE profile_identity_receipts (Id varchar(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,UserId int NOT NULL,Hash varchar(64) NOT NULL);");
    }
    protected override void Down(MigrationBuilder m)=>throw new InvalidOperationException("No se eliminan recibos durables de identidad.");
}
