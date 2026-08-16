using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MSMultilider.Seguridad.DTOs;
using MSMultilider.Seguridad.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MSMultilider.Seguridad.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUsuarioService _usuarioService;
        private readonly IConfiguration _configuration;

        public AuthController(IUsuarioService usuarioService, IConfiguration configuration)
        {
            _usuarioService = usuarioService;
            _configuration = configuration;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] AuthRequest request)
        {
            var usuario = await _usuarioService.ValidateCredentialsAsync(request.Correo, request.Password);

            if (usuario == null)
                return Unauthorized(new { message = "Las credenciales proporcionadas son incorrectas." });

            if (!usuario.Estado)
                return StatusCode(403, new { message = "Tu cuenta ha sido desactivada. Contacta al administrador." });

            var usuarioDTO = await _usuarioService.GetByIdAsync(usuario.Id);
            var token = GenerateJwtToken(usuario.Id, usuario.Correo, usuario.Nombre, usuarioDTO!);

            return Ok(new LoginResponseDTO
            {
                Message = "¡Bienvenido al sistema!",
                AccessToken = token,
                TokenType = "Bearer",
                User = usuarioDTO!
            });
        }

        [HttpGet("me")]
        [Microsoft.AspNetCore.Authorization.Authorize]
        public async Task<IActionResult> Me()
        {
            var userIdClaim = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (userIdClaim == null) return Unauthorized();

            var usuario = await _usuarioService.GetByIdAsync(int.Parse(userIdClaim));
            if (usuario == null) return NotFound();

            return Ok(usuario);
        }

        private string GenerateJwtToken(int userId, string correo, string nombre, UsuarioDTO usuarioDTO)
        {
            var jwtKey = _configuration["Jwt:Key"]!;
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,   userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, correo),
                new Claim(JwtRegisteredClaimNames.Name,  nombre),
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString())
            };

            // Incluir cada permiso del usuario como claim individual
            foreach (var rp in usuarioDTO.RolesPermisos)
            {
                claims.Add(new Claim("permission", rp.NombrePermiso));
            }

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(8),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
