using Coffee.DATA.Models;

namespace Coffee.WebUI.Models
{
    public class UserModel
    {
        public int? Id { get; set; }
        public string? Name { get; set; }
        public string? Phone { get; set; }
        public string? Email { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
        public string? Address { get; set; }
        public string? City { get; set; }
        public int? Region { get; set; }
        public int? RoleId { get; set; }
    }
}
