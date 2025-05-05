using Coffee.DATA;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Coffee.WebUI.Models;
using Coffee.DATA.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Google;
using System.Net.Mail;
using static System.Net.WebRequestMethods;
using Microsoft.AspNetCore.Http;
using Coffee.DATA.Models;
using System.Net.Http;
using Coffee.DATA.Repository;

namespace Coffee.WebUI.Controllers
{
    public class LoginController : Controller
    {
        private readonly DbCoffeeDbContext _dbCoffeeDbContext;
        private readonly IRepository<User> _userRepository;
        public LoginController(DbCoffeeDbContext dbCoffeeDbContext, IRepository<User> userRepository)
        {
            _dbCoffeeDbContext = dbCoffeeDbContext;
            _userRepository = userRepository;
        }
        //[Route("/login")]
        public IActionResult Index(string? error)
        {
            if (error == "false")
            {
                ViewData["ErrorMessage"] = "Tài khoản của bạn đã bị khoá vui lòng liên hệ Admin để biết thêm!";
            }
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Index(LoginModel model)
        {
            // Quy@0104
            if (ModelState.IsValid)
            {
                var hashedPassword = md5.ComputeMD5Hash(model.Password);
                var user = await _dbCoffeeDbContext.Users.FirstOrDefaultAsync(x => x.UserName.Contains(model.Username) && x.Password == hashedPassword);
                if (user == null)
                {
                    ViewData["ErrorMessage"] = "Tên đăng nhập hoặc mật khẩu không chính xác.";
                    return View(model);
                }
                if (user.Status == false)
                {
                    ViewData["ErrorMessage"] = "Tài khoản của bạn đã bị khoá vui lòng liên hệ Admin để biết thêm!";
                    return View(model);
                }
                var role = await _dbCoffeeDbContext.Roles.FirstOrDefaultAsync(x => x.Id == user.RoleId);
                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Name, user.Name),
                        new Claim(ClaimTypes.Role, role.Name)
                    };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                return RedirectToAction("Index", "Home");
            }
            else
            {
                return View(model);
            }
        }
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleResponse", "Login")
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (result.Succeeded)
            {
                var user = result.Principal;
                var emailClaim = user.FindFirst(ClaimTypes.Email).Value;
                var checkEmail = _dbCoffeeDbContext.Users.Where(x => x.Email == emailClaim);
                if (checkEmail.Count() < 1)
                {
                    var newUser = new User { Email = emailClaim, RoleId = 2, Status = true, CreatedOn = DateTime.Now };
                    _dbCoffeeDbContext.Users.Add(newUser);
                    _dbCoffeeDbContext.SaveChanges();
                }
                if (checkEmail.First().Status == false)
                {
                    await HttpContext.SignOutAsync();
                    return RedirectToAction("Index", "Login", new { area = "", error = "false" });
                }
            }
            return RedirectToAction("Index", "Home");
        }
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [Route("/send-otp")]
        public async Task<IActionResult> SendOTPEmail(string email)
        {
            var checkEmail = await _userRepository.GetAllAsync();

            if (checkEmail.Where(x => x.Email == email).Count() > 0)
            {
                return Json(new { success = false, message = "Email đã tồn tại!" });
            }

            // Mật khẩu ứng dụng OtpEmail : kemz hkfu jode ctfp
            Random random = new Random();
            var randomNumber = random.Next(100000, 1000000);
            MailMessage message = new MailMessage("txvq0101@gmail.com", email, "Otp", Convert.ToString(randomNumber));
            SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
            client.EnableSsl = true;
            client.DeliveryMethod = SmtpDeliveryMethod.Network;
            client.UseDefaultCredentials = false;
            client.Credentials = new System.Net.NetworkCredential("txvq0101@gmail.com", "kemz hkfu jode ctfp");
            client.Send(message);
            HttpContext.Session.SetString("OTP", Convert.ToString(randomNumber));
            //HttpContext.Session.SetString("OTP", "1");
            return Json(new { success = true, message = "Vui lòng xem email để lấy mã OTP!" });
        }
        [HttpPost]
        public async Task<IActionResult> Register(string email, string password, string otp, string name, string username)
        {
            var checkUsername = await _userRepository.GetAllAsync();

            if (checkUsername.Where(x => x.UserName == username).Count() > 0)
            {
                return Json(new { success = false, message = "Tên đăng nhập đã tồn tại!" });
            }
            var otpss = HttpContext.Session.GetString("OTP");
            if (otpss == otp)
            {
                var _user = new User { Email = email, Password = md5.ComputeMD5Hash(password), Status = true, CreatedOn = DateTime.Now, RoleId = 2, Name = name, UserName = username };
                try
                {
                    await _userRepository.InsertAsync(_user);
                    HttpContext.Session.Remove("OTP");
                    return Json(new { success = true, message = "Đăng kí thành công!" });
                }
                catch (Exception ex)
                {
                    return Json(new { success = false, message = "Fail: " + ex });
                }
            }
            else
            {
                return Json(new { success = false, message = "Mã OTP không khớp" });
            }
        }
    }
}
