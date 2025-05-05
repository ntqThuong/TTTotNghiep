using AutoMapper;
using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Coffee.WebUI.Areas.Admin.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class AccountController : Controller
    {
        private readonly IRepository<User> _userRepository;
        private readonly IMapper _mapper;
        public AccountController(IRepository<User> userRepository, IMapper mapper)
        {
            _userRepository = userRepository;
            _mapper = mapper;
        }
        public IActionResult Index()
        {
            return View();
        }
        public async Task<IActionResult> GetAllAccount()
        {
            var _user = await _userRepository.GetAllAsync();
            _user = _user.Where(x => x.RoleId != 1);
            var result = _mapper.Map<List<AccountUserModel>>(_user);
            return Json(new { success = true, result });
        }
        public async Task<IActionResult> Toggle(int Id)
        {
            try
            {
                var _user = await _userRepository.GetByIdAsync(Id);
                if (_user == null)
                {
                    return StatusCode(404);
                }
                else
                {
                    if(_user.Status == true)
                    {
                        _user.Status = false;
                        await _userRepository.UpdateAsync(_user);
                        return Json(new { success = true, message = "Đã khoá tài khoản!"});
                    }
                    else
                    {
                        _user.Status = true;
                        await _userRepository.UpdateAsync(_user);
                        return Json(new { success = true, message = "Đã mở khoá tài khoản!" });
                    }
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex.Message });
            }
        }
    }
}
