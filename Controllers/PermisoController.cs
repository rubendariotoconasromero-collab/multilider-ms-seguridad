using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Services;

namespace MSMultilider.Seguridad.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy="acceso_permisos")]
    public class PermisoController : ControllerBase
    {
        private readonly IPermisoService _service;

        public PermisoController(IPermisoService service)
        {
            _service = service;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var permisos = await _service.GetAllAsync();
            return Ok(permisos);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> Show(int id)
        {
            var permiso = await _service.GetByIdAsync(id);
            if (permiso == null) return NotFound();
            return Ok(permiso);
        }

        [HttpPost]
        public async Task<IActionResult> Store([FromBody] PermisoCreateDTO dto)
        {
            var permiso = await _service.CreateAsync(dto);
            return CreatedAtAction(nameof(Show), new { id = permiso.Id },
                new { message = "Permiso creado con éxito", data = permiso });
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Update(int id, [FromBody] PermisoCreateDTO dto)
        {
            var permiso = await _service.UpdateAsync(id, dto);
            if (permiso == null) return NotFound();
            return Ok(new { message = "Permiso actualizado", data = permiso });
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Destroy(int id)
        {
            var result = await _service.DeleteAsync(id);
            if (!result) return NotFound();
            return Ok(new { message = "Permiso eliminado correctamente" });
        }
    }
}
