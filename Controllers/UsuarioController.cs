using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Services;

namespace MSMultilider.Seguridad.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UsuarioController : ControllerBase
    {
        private readonly IUsuarioService _service;

        public UsuarioController(IUsuarioService service)
        {
            _service = service;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var usuarios = await _service.GetAllAsync();
            return Ok(usuarios);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> Show(int id)
        {
            var usuario = await _service.GetByIdAsync(id);
            if (usuario == null) return NotFound();
            return Ok(usuario);
        }

        [HttpPost]
        public async Task<IActionResult> Store([FromBody] UsuarioCreateDTO dto)
        {
            var usuario = await _service.CreateAsync(dto);
            return CreatedAtAction(nameof(Show), new { id = usuario.Id },
                new { message = "Usuario creado con éxito", data = usuario });
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Update(int id, [FromBody] UsuarioUpdateDTO dto)
        {
            var usuario = await _service.UpdateAsync(id, dto);
            if (usuario == null) return NotFound();
            return Ok(new { message = "Usuario actualizado", data = usuario });
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Destroy(int id)
        {
            var estado = await _service.ToggleEstadoAsync(id);
            var mensaje = estado ? "Usuario activado correctamente" : "Usuario desactivado correctamente";
            return Ok(new { message = mensaje, estado });
        }

        [HttpGet("{id}/asignaciones")]
        public async Task<IActionResult> GetAsignaciones(int id)
        {
            var ids = await _service.GetAsignacionesAsync(id);
            return Ok(ids);
        }

        [HttpPost("{id}/asignaciones")]
        public async Task<IActionResult> SyncAsignaciones(int id, [FromBody] SyncAsignacionesDTO dto)
        {
            await _service.SyncAsignacionesAsync(id, dto.RolPermisoIds);
            return Ok(new { message = "Accesos sincronizados correctamente" });
        }
    }
}
