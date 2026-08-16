using Microsoft.EntityFrameworkCore;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;

namespace MSMultilider.Seguridad.Services
{
    public class RolPermisoService : IRolPermisoService
    {
        private readonly ContextDatabase _context;

        public RolPermisoService(ContextDatabase context)
        {
            _context = context;
        }

        public async Task<List<RolPermisoDTO>> GetAllAsync()
        {
            var rolPermisos = await _context.RolPermisos
                .Include(rp => rp.Rol)
                .Include(rp => rp.Permiso)
                .ToListAsync();

            return rolPermisos.Select(MapToDTO).ToList();
        }

        public async Task<RolPermisoDTO?> GetByIdAsync(int id)
        {
            var rp = await _context.RolPermisos
                .Include(x => x.Rol)
                .Include(x => x.Permiso)
                .FirstOrDefaultAsync(x => x.Id == id);

            return rp == null ? null : MapToDTO(rp);
        }

        public async Task<RolPermisoDTO> CreateAsync(RolPermisoCreateDTO dto)
        {
            var rolPermiso = new RolPermiso
            {
                RolId = dto.RolId,
                PermisoId = dto.PermisoId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.RolPermisos.Add(rolPermiso);
            await _context.SaveChangesAsync();

            await _context.Entry(rolPermiso).Reference(rp => rp.Rol).LoadAsync();
            await _context.Entry(rolPermiso).Reference(rp => rp.Permiso).LoadAsync();

            return MapToDTO(rolPermiso);
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var rp = await _context.RolPermisos.FindAsync(id);
            if (rp == null) return false;

            _context.RolPermisos.Remove(rp);
            await _context.SaveChangesAsync();
            return true;
        }

        private static RolPermisoDTO MapToDTO(RolPermiso rp) => new()
        {
            Id = rp.Id,
            RolId = rp.RolId,
            NombreRol = rp.Rol.Nombre,
            PermisoId = rp.PermisoId,
            NombrePermiso = rp.Permiso.Nombre
        };
    }
}
