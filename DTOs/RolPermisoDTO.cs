namespace MSMultilider.Seguridad.DTOs
{
    public class RolPermisoDTO
    {
        public int Id { get; set; }
        public int RolId { get; set; }
        public string NombreRol { get; set; } = string.Empty;
        public int PermisoId { get; set; }
        public string NombrePermiso { get; set; } = string.Empty;
    }

    public class RolPermisoCreateDTO
    {
        public int RolId { get; set; }
        public int PermisoId { get; set; }
    }
}
