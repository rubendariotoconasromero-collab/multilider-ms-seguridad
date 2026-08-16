namespace MSMultilider.Seguridad.DTOs
{
    public class RolDTO
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public string? Descripcion { get; set; }
        public bool Estado { get; set; }
        public List<PermisoDTO> Permisos { get; set; } = new();
    }

    public class RolCreateDTO
    {
        public string Nombre { get; set; } = string.Empty;
        public string? Descripcion { get; set; }
        public bool Estado { get; set; } = true;
    }

    public class SyncPermisosDTO
    {
        public List<int> Permisos { get; set; } = new();
    }
}
