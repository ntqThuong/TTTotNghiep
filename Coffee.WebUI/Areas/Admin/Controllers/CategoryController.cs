using Coffee.DATA;
using Coffee.DATA.Common;
using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class CategoryController : Controller
    {
        private readonly IRepository<Category> _categoryRepository;
        private readonly DbCoffeeDbContext _db;

        public CategoryController(IRepository<Category> categoryRepository, DbCoffeeDbContext db)
        {
            _categoryRepository = categoryRepository;
            _db = db;
        }

        public async Task<IActionResult> Index()
        {
            var categories = await _categoryRepository.GetAllAsync();
            categories = categories.OrderByDescending(c => c.Id).ToList();
            return View(categories);
        }
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            try
            {
                var categories = await _categoryRepository.GetAllAsync();
                categories = categories.OrderByDescending(c => c.Id).ToList();
                return Json(new { success = true, categories });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        [HttpPost]
        public async Task<IActionResult> Create(Category category)
        {
            var resultCheck = _db.Categories.Where(x => x.Name == category.Name);
            if (category.Name != null && resultCheck.Count() < 1)
            {
                try
                {
                    var helper = new Helper();
                    var _category = new Category { Name = category.Name, Url = helper.ConvertToSlug(category.Name) };
                    await _categoryRepository.InsertAsync(_category);
                    return Json(new { success = true, message = "Tạo thành công!" });
                }
                catch (Exception ex)
                {
                    return Json(new { success = false, message = "Đã có lỗi xảy ra: " + ex });
                }
            }
            else
            {
                return Json(new { success = false, message = "Danh mục đã tôn tại!" });
            }
        }
        [HttpPost]
        public async Task<IActionResult> Edit(Category category)
        {
            var resultCheck = _db.Categories.Where(x => x.Name == category.Name);
            if (category.Name != null && resultCheck.Count() < 1)
            {
                try
                {
                    var helper = new Helper();
                    var _category = await _categoryRepository.GetByIdAsync(category.Id);
                    _category.Name = category.Name;
                    _category.Url = helper.ConvertToSlug(category.Name);
                    await _categoryRepository.UpdateAsync(_category);
                    return Json(new { success = true, message = "Cập nhật thành công!" });
                }
                catch (Exception ex)
                {
                    return Json(new { success = false, message = "Đã có lỗi xảy ra: " + ex });
                }
            }
            else
            {
                return Json(new { success = false, message = "Danh mục đã tôn tại!" });
            }
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                await _categoryRepository.DeleteAsync(id);
                return Json(new { success = true, message = "Xoá thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Đã có lỗi xảy ra: " + ex });
            }
        }
    }
}
