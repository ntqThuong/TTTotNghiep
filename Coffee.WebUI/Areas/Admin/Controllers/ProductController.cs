using AutoMapper;
using Coffee.DATA;
using Coffee.DATA.Common;
using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Coffee.WebUI.Areas.Admin.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class ProductController : Controller
    {
        private readonly IRepository<Product> _repository;
        private readonly IRepository<Category> _repositoryCate;
        private readonly IRepository<ProductImage> _repositoryProImage;
        private readonly IWebHostEnvironment _environment;
        private readonly IMapper _mapper;
        public ProductController(IRepository<Product> repository, DbCoffeeDbContext db, IRepository<Category> repositoryCate, IWebHostEnvironment environment, IRepository<ProductImage> repositoryProImage, IMapper mapper)
        {
            _repository = repository;
            _repositoryCate = repositoryCate;
            _environment = environment;
            _repositoryProImage = repositoryProImage;
            _mapper = mapper;
        }

        public async Task<IActionResult> Index()
        {
            ViewBag.Category = await _repositoryCate.GetAllAsync();
            return View();
        }
        public async Task<IActionResult> GetAllProduct()
        {
            var products = await _repository.GetAllAsync();
            products = products.Where(x => x.Status != null).ToList();
            var result = _mapper.Map<List<ProductModel>>(products);
            return Json(new { success = true, result });
        }
        [HttpPost]
        public async Task<IActionResult> CreateProduct(ProductModel models, IFormFile mainImage, IFormFileCollection additionalImages)
        {
            try
            {
                var helper = new Helper();
                // Lưu hình ảnh chính
                if (mainImage != null && mainImage.Length > 0)
                {
                    var urlImg = "/" + await SaveImage(mainImage);
                    var _url = helper.ConvertToSlug(models.Name);
                    var product = new Product
                    {
                        Name = models.Name,
                        Price = models.Price,
                        DiscountPrice = models.DiscountPrice ?? null,
                        Quantity = models.Quantity ?? "0",
                        Description = models.Description,
                        DescriptionShort = models.DescriptionShort,
                        Keywords = models.Keywords,
                        Image = urlImg,
                        CategoryId = models.CategoryId,
                        Url = helper.ConvertToSlug(models.Name),
                        Status = true,
                        CreatedOn = DateTime.Now,
                    };
                    var productNew = await _repository.InsertAsync(product);
                    foreach (var image in additionalImages)
                    {
                        if (image != null && image.Length > 0)
                        {
                            urlImg = "/" + await SaveImage(image);
                            var productImage = new ProductImage
                            {
                                UrlImage = urlImg,
                                ProductId = productNew.Id,
                            };
                            await _repositoryProImage.InsertAsync(productImage);
                        }
                    }
                }

                return Json(new { success = true, message = "Thêm sản phẩm thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        [HttpDelete]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var product = await _repository.GetByIdAsync(id);
                if (product != null)
                {
                    if (product.Status == true)
                    {
                        product.Status = false;
                    }
                    if (product.Status == false)
                    {
                        product.Status = true;
                    }
                    await _repository.UpdateAsync(product);
                    return Json(new { success = true, message = "Cập nhật trạng thái sản phẩm thành công!" });
                }
                else
                {
                    return Json(new { success = false, message = "Sản phẩm không tồn tại!" });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
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
    }
}
