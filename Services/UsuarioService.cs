using Microsoft.EntityFrameworkCore;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;

namespace MSMultilider.Seguridad.Services
{
    public class UsuarioService : IUsuarioService
    {
        private readonly ContextDatabase _context;

        public UsuarioService(ContextDatabase context)
        {
            _context = context;
        }

        public async Task<List<UsuarioDTO>> GetAllAsync()
        {
            var usuarios = await _context.Usuarios.ToListAsync();
            return usuarios.Select(MapToDTO).ToList();
        }

        public async Task<UsuarioDTO?> GetByIdAsync(int id)
        {
            var usuario = await _context.Usuarios
                .Include(u => u.RolPermisoUsuarios)
                    .ThenInclude(rpu => rpu.RolPermiso)
                        .ThenInclude(rp => rp.Rol)
                .Include(u => u.RolPermisoUsuarios)
                    .ThenInclude(rpu => rpu.RolPermiso)
                        .ThenInclude(rp => rp.Permiso)
                .FirstOrDefaultAsync(u => u.Id == id);

            if (usuario == null) return null;
            return MapToDTOWithPermisos(usuario);
        }

        public async Task<UsuarioDTO> CreateAsync(UsuarioCreateDTO dto)
        {
            var usuario = new Usuario
            {
                Nombre = dto.Nombre,
                Correo = dto.Correo,
                Password = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Estado = dto.Estado,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.Usuarios.Add(usuario);
            await _context.SaveChangesAsync();
            return MapToDTO(usuario);
        }

        public async Task<UsuarioDTO?> UpdateAsync(int id, UsuarioUpdateDTO dto)
        {
            var usuario = await _context.Usuarios.FindAsync(id);
            if (usuario == null) return null;

            if (!string.IsNullOrEmpty(dto.Nombre)) usuario.Nombre = dto.Nombre;
            if (!string.IsNullOrEmpty(dto.Correo)) usuario.Correo = dto.Correo;
            if (!string.IsNullOrEmpty(dto.Password)) usuario.Password = BCrypt.Net.BCrypt.HashPassword(dto.Password);
            if (dto.Estado.HasValue) usuario.Estado = dto.Estado.Value;
            usuario.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return MapToDTO(usuario);
        }

        public async Task<bool> ToggleEstadoAsync(int id)
        {
            var usuario = await _context.Usuarios.FindAsync(id);
            if (usuario == null) return false;

            usuario.Estado = !usuario.Estado;
            usuario.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return usuario.Estado;
        }

        public async Task<Usuario?> ValidateCredentialsAsync(string correo, string password)
        {
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.Correo == correo);
            if (usuario == null) return null;
            if (!BCrypt.Net.BCrypt.Verify(password, usuario.Password)) return null;
            return usuario;
        }

        public async Task<List<int>> GetAsignacionesAsync(int userId)
        {
            return await _context.RolPermisoUsuarios
                .Where(rpu => rpu.UserId == userId)
                .Select(rpu => rpu.RolPermisoId)
                .ToListAsync();
        }

        public async Task SyncAsignacionesAsync(int userId, List<int> rolPermisoIds)
        {
            var existentes = _context.RolPermisoUsuarios.Where(rpu => rpu.UserId == userId);
            _context.RolPermisoUsuarios.RemoveRange(existentes);

            var nuevas = rolPermisoIds.Select(rpId => new RolPermisoUsuario
            {
                UserId = userId,
                RolPermisoId = rpId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });

            _context.RolPermisoUsuarios.AddRange(nuevas);
            await _context.SaveChangesAsync();
        }

        private static UsuarioDTO MapToDTO(Usuario u) => new()
        {
            Id = u.Id,
            Nombre = u.Nombre,
            Correo = u.Correo,
            Estado = u.Estado
        };

        private static UsuarioDTO MapToDTOWithPermisos(Usuario u) => new()
        {
            Id = u.Id,
            Nombre = u.Nombre,
            Correo = u.Correo,
            Estado = u.Estado,
            RolesPermisos = u.RolPermisoUsuarios.Select(rpu => new RolPermisoAsignadoDTO
            {
                RolPermisoId = rpu.RolPermisoId,
                RolId = rpu.RolPermiso.RolId,
                NombreRol = rpu.RolPermiso.Rol.Nombre,
                PermisoId = rpu.RolPermiso.PermisoId,
                NombrePermiso = rpu.RolPermiso.Permiso.Nombre
            }).ToList()
        };
    }
}
