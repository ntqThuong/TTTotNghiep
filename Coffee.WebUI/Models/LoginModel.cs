using System.ComponentModel.DataAnnotations;

namespace Coffee.WebUI.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Yêu cầu nhập tên đăng nhập")]
        public string Username { get; set; }
        [Required(ErrorMessage = "Yêu cầu nhập mật khẩu")]
        public string Password { get; set; }
    }
}
