using Microsoft.EntityFrameworkCore;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Models;
using MSMultilider.Seguridad.Repositories;

namespace MSMultilider.Seguridad.Services
{
    public class PermisoService : IPermisoService
    {
        private readonly ContextDatabase _context;

        public PermisoService(ContextDatabase context)
        {
            _context = context;
        }

        public async Task<List<PermisoDTO>> GetAllAsync()
        {
            var permisos = await _context.Permisos.ToListAsync();
            return permisos.Select(MapToDTO).ToList();
        }

        public async Task<PermisoDTO?> GetByIdAsync(int id)
        {
            var permiso = await _context.Permisos.FindAsync(id);
            return permiso == null ? null : MapToDTO(permiso);
        }

        public async Task<PermisoDTO> CreateAsync(PermisoCreateDTO dto)
        {
            var permiso = new Permiso
            {
                Nombre = dto.Nombre,
                Descripcion = dto.Descripcion,
                Estado = dto.Estado,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.Permisos.Add(permiso);
            await _context.SaveChangesAsync();
            return MapToDTO(permiso);
        }

        public async Task<PermisoDTO?> UpdateAsync(int id, PermisoCreateDTO dto)
        {
            var permiso = await _context.Permisos.FindAsync(id);
            if (permiso == null) return null;

            permiso.Nombre = dto.Nombre;
            permiso.Descripcion = dto.Descripcion;
            permiso.Estado = dto.Estado;
            permiso.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return MapToDTO(permiso);
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var permiso = await _context.Permisos.FindAsync(id);
            if (permiso == null) return false;

            _context.Permisos.Remove(permiso);
            await _context.SaveChangesAsync();
            return true;
        }

        private static PermisoDTO MapToDTO(Permiso p) => new()
        {
            Id = p.Id,
            Nombre = p.Nombre,
            Descripcion = p.Descripcion
        };
    }
}
