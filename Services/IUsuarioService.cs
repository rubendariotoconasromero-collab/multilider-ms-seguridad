using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Models;

namespace MSMultilider.Seguridad.Services
{
    public interface IUsuarioService
    {
        Task<List<UsuarioDTO>> GetAllAsync();
        Task<UsuarioDTO?> GetByIdAsync(int id);
        Task<UsuarioDTO> CreateAsync(UsuarioCreateDTO dto);
        Task<UsuarioDTO?> UpdateAsync(int id, UsuarioUpdateDTO dto);
        Task<bool> ToggleEstadoAsync(int id);
        Task<Usuario?> ValidateCredentialsAsync(string correo, string password);
        Task<List<int>> GetAsignacionesAsync(int userId);
        Task SyncAsignacionesAsync(int userId, List<int> rolPermisoIds);
    }
}
