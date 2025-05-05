using Coffee.DATA;
using Coffee.DATA.Common;
using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Coffee.WebUI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Coffee.WebUI.Controllers
{
    
    public class CartController : Controller
    {
        private readonly DbCoffeeDbContext _dbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IRepository<Product> _productsRepository;

        public CartController(IHttpContextAccessor httpContextAccessor, DbCoffeeDbContext dbContext, IRepository<Product> productsRepository)
        {
            _httpContextAccessor = httpContextAccessor;
            _dbContext = dbContext;
            _productsRepository = productsRepository;
        }
        [Authorize]
        public IActionResult Index()
        {
            var _email = User.FindFirst(ClaimTypes.Email)?.Value;
            var _user = _dbContext.Users.First(x => x.Email == _email);
            var httpContext = _httpContextAccessor.HttpContext;
            var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
            if (CartModels.Count() > 0)
            {
                ViewBag.Cart = "True";
            }
            ViewBag.Province = _user.Province;
            ViewBag.District = _user.District;
            ViewBag.Town = _user.Town;
            ViewBag.Address = _user.Address;
            return View();
        }

        public IActionResult GetCart()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
            double totalPrice = (double)CartModels.Sum(item => item.ProductModel.Price * item.Quantity);
            int CartCount = CartModels.Sum(item => item.Quantity);

            var responseData = new
            {
                CartModels,
                totalPrice,
                CartCount,
            };

            return Json(responseData);
        }


        [HttpPost]
        public IActionResult AddToCart(Product product, int quantity)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
            var existingItem = CartModels.FirstOrDefault(item => item.ProductModel.ProductId == product.Id);

            if (existingItem != null)
            {
                existingItem.Quantity += quantity;
            }
            else
            {
                var _product = _dbContext.Products.Where(p => p.Id == product.Id).FirstOrDefault();
                CartModels.Add(new CartModel { ProductModel = MapToProductModel(_product), Quantity = quantity });
            }

            httpContext.Session.Set("Cart", CartModels);
            return Json(new { success = true });
        }

        [HttpPost]
        public async Task<IActionResult> UpdateQuantity(int productId, int quantity)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
            var CartModelToUpdate = CartModels.FirstOrDefault(item => item.ProductModel.ProductId == productId);

            if (CartModelToUpdate != null)
            {
                CartModelToUpdate.Quantity += quantity;
                var _product = await _productsRepository.GetByIdAsync(productId);
                if (CartModelToUpdate.Quantity > Convert.ToInt32(_product.Quantity))
                {
                    return Json(new { success = false, message = "Số lượng sản phẩm hiện có đã đạt tối đa!" });
                }
                if (CartModelToUpdate.Quantity <= 0)
                {
                    CartModels.Remove(CartModelToUpdate);
                }
                httpContext.Session.Set("Cart", CartModels);
            }

            return Json(new { success = true });
        }

        [HttpPost]
        public IActionResult RemoveFromCart(int productId)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
            var itemToRemove = CartModels.FirstOrDefault(item => item.ProductModel.ProductId == productId);

            if (itemToRemove != null)
            {
                CartModels.Remove(itemToRemove);
                httpContext.Session.Set("Cart", CartModels);
            }
            return Json(new { success = true });
        }
        private ProductModel MapToProductModel(Product productFromDb)
        {
            if (productFromDb.DiscountPrice != null)
            {
                return new ProductModel
                {
                    ProductId = productFromDb.Id,
                    Name = productFromDb.Name,
                    Url = productFromDb.Image,
                    Description = productFromDb.Description,
                    Price = productFromDb.DiscountPrice,
                    categoryId = productFromDb.CategoryId,
                };
            }
            return new ProductModel
            {
                ProductId = productFromDb.Id,
                Name = productFromDb.Name,
                Url = productFromDb.Image,
                Description = productFromDb.Description,
                Price = productFromDb.Price,
                categoryId = productFromDb.CategoryId,
            };
        }
    }
}
