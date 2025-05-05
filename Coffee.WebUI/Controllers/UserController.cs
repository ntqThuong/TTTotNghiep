using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
//using Twilio;
//using Twilio.Rest.Api.V2010.Account;
//using Twilio.Types;

namespace Coffee.WebUI.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        private readonly IRepository<User> _userRepository;
        public UserController(IRepository<User> userRepository)
        {
            _userRepository = userRepository;
        }
        public async Task<IActionResult> Index()
        {
            var _user = await _userRepository.GetAllAsync();
            var _userDetail = _user.First(x => x.Email == User.FindFirst(ClaimTypes.Email)?.Value);
            return View(_userDetail);
        }
        [HttpPost]
        public async Task<IActionResult> Index(User user)
        {
            try
            {
                var _user = await _userRepository.GetByIdAsync(user.Id);
                if (_user != null)
                {
                    _user.Name = user.Name;
                    _user.Town = user.Town;
                    _user.Address = user.Address;
                    _user.Province = user.Province;
                    _user.District = user.District;
                    _user.Phone = user.Phone;
                    await _userRepository.UpdateAsync(_user);
                    return Json(new { success = true, message = "Cập nhật thành công!" });
                }
                else
                {
                    return StatusCode(404);
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
    }
}
