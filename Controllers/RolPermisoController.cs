using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Services;

namespace MSMultilider.Seguridad.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class RolPermisoController : ControllerBase
    {
        private readonly IRolPermisoService _service;

        public RolPermisoController(IRolPermisoService service)
        {
            _service = service;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var rolPermisos = await _service.GetAllAsync();
            return Ok(rolPermisos);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> Show(int id)
        {
            var rp = await _service.GetByIdAsync(id);
            if (rp == null) return NotFound();
            return Ok(rp);
        }

        [HttpPost]
        public async Task<IActionResult> Store([FromBody] RolPermisoCreateDTO dto)
        {
            var rp = await _service.CreateAsync(dto);
            return CreatedAtAction(nameof(Show), new { id = rp.Id },
                new { message = "Asignación creada con éxito", data = rp });
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Destroy(int id)
        {
            var result = await _service.DeleteAsync(id);
            if (!result) return NotFound();
            return Ok(new { message = "Asignación eliminada correctamente" });
        }
    }
}
