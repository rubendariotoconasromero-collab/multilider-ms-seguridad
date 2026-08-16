using MSMultilider.Seguridad.DTOs;

namespace MSMultilider.Seguridad.Services
{
    public interface IPermisoService
    {
        Task<List<PermisoDTO>> GetAllAsync();
        Task<PermisoDTO?> GetByIdAsync(int id);
        Task<PermisoDTO> CreateAsync(PermisoCreateDTO dto);
        Task<PermisoDTO?> UpdateAsync(int id, PermisoCreateDTO dto);
        Task<bool> DeleteAsync(int id);
    }
}
