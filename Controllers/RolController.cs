using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Services;

namespace MSMultilider.Seguridad.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy="acceso_roles")]
    public class RolController : ControllerBase
    {
        private readonly IRolService _service;

        public RolController(IRolService service)
        {
            _service = service;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var roles = await _service.GetAllAsync();
            return Ok(roles);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> Show(int id)
        {
            var rol = await _service.GetByIdAsync(id);
            if (rol == null) return NotFound();
            return Ok(rol);
        }

        [HttpPost]
        public async Task<IActionResult> Store([FromBody] RolCreateDTO dto)
        {
            var rol = await _service.CreateAsync(dto);
            return CreatedAtAction(nameof(Show), new { id = rol.Id },
                new { message = "Rol creado con éxito", data = rol });
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Update(int id, [FromBody] RolCreateDTO dto)
        {
            var rol = await _service.UpdateAsync(id, dto);
            if (rol == null) return NotFound();
            return Ok(new { message = "Rol actualizado", data = rol });
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Destroy(int id)
        {
            var estado = await _service.ToggleEstadoAsync(id);
            var mensaje = estado ? "Rol activado correctamente" : "Rol desactivado correctamente";
            return Ok(new { message = mensaje, estado });
        }

        [HttpGet("{id}/permisos")]
        public async Task<IActionResult> GetPermisos(int id)
        {
            var permisoIds = await _service.GetPermisosAsync(id);
            return Ok(permisoIds);
        }

        [HttpPost("{id}/permisos/sync")]
        public async Task<IActionResult> SyncPermisos(int id, [FromBody] SyncPermisosDTO dto)
        {
            await _service.SyncPermisosAsync(id, dto.Permisos);
            return Ok(new { message = "Permisos sincronizados correctamente" });
        }
    }
}
