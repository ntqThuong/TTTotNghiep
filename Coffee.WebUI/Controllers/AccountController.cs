using Coffee.DATA.Common;
using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Microsoft.AspNetCore.Mvc;
using System.Net.Mail;

namespace Coffee.WebUI.Controllers
{
    public class AccountController : Controller
    {
        private readonly IRepository<User> _userRepostory;
        public AccountController(IRepository<User> userRepostory)
        {
            _userRepostory = userRepostory;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Index(string email)
        {
            var _user = await _userRepostory.GetAllAsync();
            var _userEmail = _user.Where(x => x.Email.Contains(email));
            if (_userEmail.Any())
            {
                // Mật khẩu ứng dụng OtpEmail : kemz hkfu jode ctfp
                Random random = new Random();
                var randomNumber = random.Next(100000, 1000000);
                MailMessage message = new MailMessage("txvq0101@gmail.com", email, "CodeResetPassword", "https://localhost:7263/Account/Reset?code=" + Convert.ToString(randomNumber) + "&email=" + email);
                SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
                client.EnableSsl = true;
                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                client.UseDefaultCredentials = false;
                client.Credentials = new System.Net.NetworkCredential("txvq0101@gmail.com", "kemz hkfu jode ctfp");
                client.Send(message);
                HttpContext.Session.SetString("CodeResetPassword", Convert.ToString(randomNumber));
                return Json(new { success = true, message = "Vui lòng check email!" });
            }
            else
            {
                return Json(new { success = false, message = "Không tồn tại email!" });
            }
        }
        public IActionResult Reset(string code, string email)
        {
            var codeResetPass = HttpContext.Session.GetString("CodeResetPassword");
            if (codeResetPass == code)
            {
                ViewBag.Code = code;
                ViewBag.Email = email;
                return View();
            }
            return StatusCode(404);
        }
        [HttpPost]
        public async Task<IActionResult> ResetPassword(string password, string email)
        {
            try
            {
                var _user = await _userRepostory.GetAllAsync();
                var _userDetail = _user.First(x => x.Email.Contains(email));
                _userDetail.Password = md5.ComputeMD5Hash(password);
                await _userRepostory.UpdateAsync(_userDetail);
                HttpContext.Session.Remove("CodeResetPassword");
                return Json(new { success = true, message = "Cập nhật mật khẩu thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail :" + ex.Message });
            }
        }
    }
}
