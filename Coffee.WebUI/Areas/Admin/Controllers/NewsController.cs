using Coffee.DATA.Common;
using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NuGet.Protocol.Core.Types;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Text.Json;
using AutoMapper;
using Coffee.WebUI.Areas.Admin.Model;

namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class NewsController : Controller
    {
        private readonly IRepository<New> _newRepository;
        private readonly IRepository<User> _userRepository;
        private readonly IWebHostEnvironment _environment;
        private readonly IMapper _mapper;
        public NewsController(IRepository<New> newRepository, IWebHostEnvironment environment, IRepository<User> userRepository, IMapper mapper)
        {
            _newRepository = newRepository;
            _environment = environment;
            _userRepository = userRepository;
            _mapper = mapper;
        }

        public async Task<IActionResult> Index()
        {
            ViewBag.User = await _userRepository.GetAllAsync();
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Index(New model, IFormFile mainImage)
        {
            try
            {
                var helper = new Helper();
                var urlImg = "/" + await SaveImage(mainImage);
                var _user = await _userRepository.GetAllAsync();
                var _new = new New
                {
                    Title = model.Title,
                    Content = model.Content,
                    Description = model.Description,
                    Keywords = model.Keywords,
                    Image = urlImg,
                    Url = helper.ConvertToSlug(model.Title),
                    UserId = _user.First(x => x.Email == User.FindFirst(ClaimTypes.Email)?.Value).Id,
                    Status = false,
                    CreatedOn = DateTime.Now,
                };
                await _newRepository.InsertAsync(_new);
                return Json(new { success = true, message = "Thêm bài viết thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
        [HttpPut]
        public async Task<IActionResult> Index(New model, IFormFile mainImage, int Id)
        {
            try
            {
                var helper = new Helper();

                var _user = await _userRepository.GetAllAsync();
                var _new = await _newRepository.GetByIdAsync(Id);

                _new.Title = model.Title;
                _new.Content = model.Content;
                _new.Description = model.Description;
                _new.Keywords = model.Keywords;
                _new.Url = helper.ConvertToSlug(model.Title);
                if (mainImage != null)
                {
                    if (!string.IsNullOrEmpty(_new.Image))
                    {
                        string imagePath = "wwwroot" + _new.Image;
                        var t = System.IO.File.Exists(imagePath);
                        if (System.IO.File.Exists(imagePath))
                        {
                            System.IO.File.Delete(imagePath);
                        }
                    }
                    _new.Image = "/" + await SaveImage(mainImage);
                }
                await _newRepository.UpdateAsync(_new);
                return Json(new { success = true, message = "Sửa bài viết thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
        [HttpDelete]
        public async Task<IActionResult> Index(int Id)
        {
            try
            {
                var _new = await _newRepository.GetByIdAsync(Id);
                if (!string.IsNullOrEmpty(_new.Image))
                {
                    string imagePath = "wwwroot" + _new.Image;
                    var t = System.IO.File.Exists(imagePath);
                    if (System.IO.File.Exists(imagePath))
                    {
                        System.IO.File.Delete(imagePath);
                    }
                }
                await _newRepository.DeleteAsync(Id);
                return Json(new { success = true, message = "Xoá bài viết thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
        [HttpPost]
        public async Task<IActionResult> BrowseNews(int Id)
        {
            try
            {
                var _new = await _newRepository.GetByIdAsync(Id);
                _new.Status = true;
                await _newRepository.UpdateAsync(_new);
                return Json(new { success = true, message = "Duyệt bài viết thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
        public async Task<IActionResult> GetAllNews()
        {
            try
            {
                var _new = await _newRepository.GetAllAsync();
                var _user = await _userRepository.GetAllAsync();
                var result = _mapper.Map<List<NewModel>>(_new);
                foreach (var item in result)
                {
                    item.UserName = _user.First(x => x.Id == item.UserId).Name;
                }
                return Json(new { success = true, result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
        public async Task<string> SaveImage(IFormFile image)
        {
            // Tạo tên tệp duy nhất cho hình ảnh
            var fileName = Guid.NewGuid().ToString() + Path.GetExtension(image.FileName);
            var imagePath = Path.Combine(_environment.WebRootPath, "assets", "news", fileName);

            // Lưu hình ảnh vào thư mục wwwroot/assets/product
            using (var stream = new FileStream(imagePath, FileMode.Create))
            {
                await image.CopyToAsync(stream);
            }

            // Trả về đường dẫn tương đối của hình ảnh
            return Path.Combine("assets", "news", fileName).Replace("\\", "/");
        }
    }
}
