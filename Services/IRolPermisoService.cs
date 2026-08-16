using MSMultilider.Seguridad.DTOs;

namespace MSMultilider.Seguridad.Services
{
    public interface IRolPermisoService
    {
        Task<List<RolPermisoDTO>> GetAllAsync();
        Task<RolPermisoDTO?> GetByIdAsync(int id);
        Task<RolPermisoDTO> CreateAsync(RolPermisoCreateDTO dto);
        Task<bool> DeleteAsync(int id);
    }
}
