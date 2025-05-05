using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;
using System.Text.Json;
using AutoMapper;
using Coffee.WebUI.Areas.Admin.Model;

namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class ProductDetailController : Controller
    {
        private readonly IRepository<ProductImage> _repository;
        private readonly IRepository<Product> _repositoryProduct;
        private readonly IRepository<Category> _repositoryCate;
        private readonly IWebHostEnvironment _environment;
        private readonly IMapper _mapper;
        public ProductDetailController(IRepository<ProductImage> repository, IRepository<Product> repositoryProduct, IRepository<Category> repositoryCate, IWebHostEnvironment environment, IMapper mapper)
        {
            _repository = repository;
            _repositoryProduct = repositoryProduct;
            _repositoryCate = repositoryCate;
            _environment = environment;
            _mapper = mapper;
        }
        public async Task<IActionResult> Index(int id)
        {
            if (id > 0)
            {
                try
                {
                    var _product = await _repositoryProduct.GetByIdAsync(id);
                    ViewData["Title"] = _product.Name;
                    ViewBag.Category = await _repositoryCate.GetAllAsync();
                    return View();
                }
                catch
                {
                    return StatusCode(404);
                }
            }
            else
            {
                return RedirectToAction("Index", "Product", new { area = "Admin" });
            }
        }
        public async Task<IActionResult> GetProductDetail(int id)
        {
            try
            {
                var _product = await _repositoryProduct.GetByIdAsync(id);
                var _productImg = await _repository.GetAllAsync();
                _productImg = _productImg.Where(x => x.ProductId == _product.Id);
                var result = new
                {
                    success = true,
                    product = _mapper.Map<ProductModel>(_product),
                    productImg = _mapper.Map<List<ProductImageModel>>(_productImg),
                };
                return Json(result);
            }
            catch (Exception ex)
            {
                return StatusCode(404);
            }
        }

        public async Task<IActionResult> UpdateImgMain(IFormFile mainImage, int id)
        {
            try
            {
                var _img = await _repositoryProduct.GetByIdAsync(id);
                string imageUrl = "";
                if (!string.IsNullOrEmpty(_img.Image))
                {
                    string imagePath = "wwwroot" + _img.Image;
                    var t = System.IO.File.Exists(imagePath);
                    if (System.IO.File.Exists(imagePath))
                    {
                        System.IO.File.Delete(imagePath);
                    }
                    imageUrl = "/" + await SaveImage(mainImage);
                    _img.Image = imageUrl;
                    await _repositoryProduct.UpdateAsync(_img);
                }
                return Json(new { success = true, imageUrl, message = "Cập nhật ảnh thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex });
            }

        }
        public async Task<IActionResult> UpdateImgAuxiliary(IFormFile mainImage, int id)
        {
            try
            {
                var _img = await _repository.GetByIdAsync(id);
                string imageUrl = "";
                if (!string.IsNullOrEmpty(_img.UrlImage))
                {
                    string imagePath = "wwwroot" + _img.UrlImage;
                    var t = System.IO.File.Exists(imagePath);
                    if (System.IO.File.Exists(imagePath))
                    {
                        System.IO.File.Delete(imagePath);
                    }
                    imageUrl = "/" + await SaveImage(mainImage);
                    _img.UrlImage = imageUrl;
                    await _repository.UpdateAsync(_img);
                }
                return Json(new { success = true, imageUrl, message = "Cập nhật ảnh thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex });
            }
        }
        public async Task<string> SaveImage(IFormFile image)
        {
            // Tạo tên tệp duy nhất cho hình ảnh
            var fileName = Guid.NewGuid().ToString() + Path.GetExtension(image.FileName);
            var imagePath = Path.Combine(_environment.WebRootPath, "assets", "product", fileName);

            // Lưu hình ảnh vào thư mục wwwroot/assets/product
            using (var stream = new FileStream(imagePath, FileMode.Create))
            {
                await image.CopyToAsync(stream);
            }

            // Trả về đường dẫn tương đối của hình ảnh
            return Path.Combine("assets", "product", fileName).Replace("\\", "/");
        }
        [HttpPost]
        public async Task<IActionResult> UpdateProduct(Product model)
        {
            try
            {
                var _product = await _repositoryProduct.GetByIdAsync(model.Id);
                if (_product != null)
                {
                    _product.Name = model.Name;
                    _product.Description = model.Description;
                    _product.Price = model.Price;
                    _product.CategoryId = model.CategoryId;
                    _product.Keywords = model.Keywords;
                    _product.Quantity = model.Quantity;
                    _product.DescriptionShort = model.DescriptionShort;
                    _product.DiscountPrice = model.DiscountPrice;
                    await _repositoryProduct.UpdateAsync(_product);
                    return Json(new { success = true, message = "Cập nhật thành công!" });
                }
                else
                {
                    return Json(new { success = false, message = "Không tồn tại sản phẩm" });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex });
            }
        }
    }
}
