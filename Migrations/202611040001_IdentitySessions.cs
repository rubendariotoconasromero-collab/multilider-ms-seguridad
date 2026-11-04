using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MSMultilider.Seguridad.Repositories;
namespace MSMultilider.Seguridad.Migrations;
[DbContext(typeof(ContextDatabase)), Migration("202611040001_IdentitySessions")]
public sealed class IdentitySessions:Migration {
    protected override void Up(MigrationBuilder migration) {
        // Baseline is additive: existing Laravel-compatible users/assignments are never recreated.
        migration.Sql("CREATE TABLE IF NOT EXISTS users (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,nombre VARCHAR(255) NOT NULL,correo VARCHAR(255) NOT NULL UNIQUE,password VARCHAR(255) NOT NULL,estado TINYINT(1) NOT NULL DEFAULT 1,created_at DATETIME(6) NULL,updated_at DATETIME(6) NULL) CHARACTER SET utf8mb4;");
        migration.Sql("CREATE TABLE IF NOT EXISTS roles (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,nombre VARCHAR(255) NOT NULL,descripcion TEXT NULL,estado TINYINT(1) NOT NULL DEFAULT 1,created_at DATETIME(6) NULL,updated_at DATETIME(6) NULL) CHARACTER SET utf8mb4;");
        migration.Sql("CREATE TABLE IF NOT EXISTS permisos (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,nombre VARCHAR(255) NOT NULL,descripcion TEXT NULL,estado TINYINT(1) NOT NULL DEFAULT 1,created_at DATETIME(6) NULL,updated_at DATETIME(6) NULL) CHARACTER SET utf8mb4;");
        migration.Sql("CREATE TABLE IF NOT EXISTS rol_permiso (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,rol_id INT NOT NULL,permiso_id INT NOT NULL,created_at DATETIME(6) NULL,updated_at DATETIME(6) NULL,UNIQUE KEY rol_permiso_unique(rol_id,permiso_id),FOREIGN KEY(rol_id) REFERENCES roles(id) ON DELETE CASCADE,FOREIGN KEY(permiso_id) REFERENCES permisos(id) ON DELETE CASCADE);");
        migration.Sql("CREATE TABLE IF NOT EXISTS rol_permiso_usuario (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,rol_permiso_id INT NOT NULL,created_at DATETIME(6) NULL,updated_at DATETIME(6) NULL,UNIQUE KEY asignacion_unique(user_id,rol_permiso_id),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(rol_permiso_id) REFERENCES rol_permiso(id) ON DELETE CASCADE);");
        migration.Sql("ALTER TABLE users ADD COLUMN auth_version BIGINT NOT NULL DEFAULT 0;");
        migration.Sql("CREATE TABLE auth_sessions (jti VARCHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,user_id INT NOT NULL,version BIGINT NOT NULL,expires_at DATETIME(6) NOT NULL,revoked_at DATETIME(6) NULL,INDEX ix_auth_sessions_user(user_id),INDEX ix_auth_sessions_expiry(expires_at));");
        migration.Sql("CREATE TABLE auth_mutex (id INT NOT NULL PRIMARY KEY);");
        migration.Sql("INSERT INTO auth_mutex (id) VALUES (1);");
    }
    protected override void Down(MigrationBuilder migration) {
        migration.Sql("DROP TABLE auth_sessions;");
        migration.Sql("DROP TABLE auth_mutex;");
        migration.Sql("ALTER TABLE users DROP COLUMN auth_version;");
        // Core tables intentionally survive rollback. Never destroy identities on infrastructure rollback.
    }
}
