using MSMultilider.Seguridad.DTOs;

namespace MSMultilider.Seguridad.Services
{
    public interface IRolService
    {
        Task<List<RolDTO>> GetAllAsync();
        Task<RolDTO?> GetByIdAsync(int id);
        Task<RolDTO> CreateAsync(RolCreateDTO dto);
        Task<RolDTO?> UpdateAsync(int id, RolCreateDTO dto);
        Task<bool> ToggleEstadoAsync(int id);
        Task<List<int>> GetPermisosAsync(int rolId);
        Task SyncPermisosAsync(int rolId, List<int> permisoIds);
    }
}
