using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Text.Json;
using Coffee.WebUI.Areas.Admin.Model;

namespace Coffee.WebUI.Controllers
{
    [Authorize]
    public class HistoryOrderController : Controller
    {
        private readonly IRepository<Order> _orderRepository;
        private readonly IRepository<OrderDetail> _orderDetailRepository;
        private readonly IRepository<User> _userRepository;
        private readonly IRepository<Product> _productRepository;
        public HistoryOrderController(IRepository<Order> orderRepository, IRepository<User> userRepository, IRepository<OrderDetail> orderDetailRepository, IRepository<Product> productRepository)
        {
            _orderRepository = orderRepository;
            _userRepository = userRepository;
            _orderDetailRepository = orderDetailRepository;
            _productRepository = productRepository;
        }
        public IActionResult Index()
        {
            return View();
        }
        public async Task<IActionResult> GetAllOrder()
        {
            try
            {
                var _user = await _userRepository.GetAllAsync();
                var _userId = _user.First(x => x.Email == User.FindFirst(ClaimTypes.Email)?.Value).Id;
                var _orderDetail = await _orderDetailRepository.GetAllAsync();
                var _order = await _orderRepository.GetAllAsync();
                _order = _order.Where(x => x.UserId == _userId);
                if (_order.Count() < 1)
                {
                    return Json(new { success = false, message = "Bạn chưa mua hàng lần nào!" });
                }
                var result = new List<HistoryOrderModel>();
                foreach (var order in _order)
                {
                    var user = _user.FirstOrDefault(x => x.Id == order.UserId);
                    var staff = _user.FirstOrDefault(x => x.Id == order.StaffId);
                    decimal total = (decimal)_orderDetail.Where(x => x.OrderId == order.Id).Sum(x => x.Price);

                    result.Add(new HistoryOrderModel
                    {
                        Id = order.Id,
                        Name = user != null ? user.Name : string.Empty,
                        FinishDay = (DateTime)order.CreatedOn,
                        Total = total,
                        PayStatus = (bool)order.Status,
                        OrderStatus = (bool)order.OrderStatus,
                        StaffName = staff != null ? staff.Name : string.Empty
                    });
                }
                result = result.OrderByDescending(x => x.Id).ToList();
                return Json(new { success = true, result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex.Message });
            }
        }
        public async Task<IActionResult> GetAllOrderDetail(int Id)
        {
            try
            {
                var _orderDetail = await _orderDetailRepository.GetAllAsync();
                var _product = await _productRepository.GetAllAsync();
                _orderDetail = _orderDetail.Where(x => x.OrderId == Id);
                var result = new List<OrderDetailModel>();
                foreach (var item in _orderDetail)
                {
                    result.Add(new OrderDetailModel
                    {
                        Id = item.Id,
                        ProductName = _product.First(x => x.Id == item.ProductId).Name,
                        Quantity = item.Quanlity,
                    });
                }
                return Json(new { success = true, result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }
    }
}
