using Microsoft.EntityFrameworkCore;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;

namespace MSMultilider.Seguridad.Services
{
    public class RolService : IRolService
    {
        private readonly ContextDatabase _context;

        public RolService(ContextDatabase context)
        {
            _context = context;
        }

        public async Task<List<RolDTO>> GetAllAsync()
        {
            var roles = await _context.Roles
                .Include(r => r.RolPermisos)
                    .ThenInclude(rp => rp.Permiso)
                .ToListAsync();

            return roles.Select(MapToDTO).ToList();
        }

        public async Task<RolDTO?> GetByIdAsync(int id)
        {
            var rol = await _context.Roles
                .Include(r => r.RolPermisos)
                    .ThenInclude(rp => rp.Permiso)
                .FirstOrDefaultAsync(r => r.Id == id);

            return rol == null ? null : MapToDTO(rol);
        }

        public async Task<RolDTO> CreateAsync(RolCreateDTO dto)
        {
            if(await _context.Roles.AnyAsync(x=>x.Nombre==dto.Nombre)) throw new ArgumentException();
            var rol = new Rol
            {
                Nombre = dto.Nombre,
                Descripcion = dto.Descripcion,
                Estado = dto.Estado,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.Roles.Add(rol);
            await _context.SaveChangesAsync();
            return MapToDTO(rol);
        }

        public async Task<RolDTO?> UpdateAsync(int id, RolCreateDTO dto)
        {
            var rol = await _context.Roles.FindAsync(id);
            if (rol == null) return null;

            if(await _context.Roles.AnyAsync(x=>x.Nombre==dto.Nombre && x.Id!=id)) throw new ArgumentException();
            rol.Nombre = dto.Nombre;
            rol.Descripcion = dto.Descripcion;
            rol.Estado = dto.Estado;
            rol.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return MapToDTO(rol);
        }

        public async Task<bool> ToggleEstadoAsync(int id)
        {
            var rol = await _context.Roles.FindAsync(id);
            if (rol == null) return false;

            rol.Estado = !rol.Estado;
            rol.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return rol.Estado;
        }

        public async Task<List<int>> GetPermisosAsync(int rolId)
        {
            return await _context.RolPermisos
                .Where(rp => rp.RolId == rolId)
                .Select(rp => rp.PermisoId)
                .ToListAsync();
        }

        public async Task SyncPermisosAsync(int rolId, List<int> permisoIds)
        {
            if (!await _context.Roles.AnyAsync(x=>x.Id==rolId)) throw new KeyNotFoundException();
            permisoIds=permisoIds.Distinct().ToList();
            if(await _context.Permisos.CountAsync(x=>permisoIds.Contains(x.Id))!=permisoIds.Count) throw new ArgumentException();
            var existentes=await _context.RolPermisos.Where(x=>x.RolId==rolId).ToListAsync();
            var obsolete=existentes.Where(x=>!permisoIds.Contains(x.PermisoId)).ToList();
            var obsoleteIds=obsolete.Select(x=>x.Id).ToList();
            _context.RolPermisoUsuarios.RemoveRange(await _context.RolPermisoUsuarios.Where(x=>obsoleteIds.Contains(x.RolPermisoId)).ToListAsync());
            _context.RolPermisos.RemoveRange(obsolete);
            foreach(var id in permisoIds.Where(id=>!existentes.Any(x=>x.PermisoId==id)))
                _context.RolPermisos.Add(new RolPermiso {RolId=rolId,PermisoId=id,CreatedAt=DateTime.UtcNow,UpdatedAt=DateTime.UtcNow});
            await _context.SaveChangesAsync();
        }

        private static RolDTO MapToDTO(Rol r) => new()
        {
            Id = r.Id,
            Nombre = r.Nombre,
            Descripcion = r.Descripcion,
            Estado = r.Estado,
            Permisos = r.RolPermisos.Select(rp => new PermisoDTO
            {
                Id = rp.Permiso.Id,
                Nombre = rp.Permiso.Nombre,
                Descripcion = rp.Permiso.Descripcion,
                Estado = rp.Permiso.Estado
            }).ToList()
        };
    }
}
