using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Coffee.WebUI.Areas.Admin.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class HistoryOrderController : Controller
    {
        private readonly IRepository<Order> _orderRepository;
        private readonly IRepository<OrderDetail> _orderDetailRepository;
        private readonly IRepository<User> _userRepository;
        public HistoryOrderController(IRepository<Order> orderRepository, IRepository<OrderDetail> orderDetailRepository, IRepository<User> userRepository)
        {
            _orderRepository = orderRepository;
            _orderDetailRepository = orderDetailRepository;
            _userRepository = userRepository;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> GetDateHistoryOrder(DateTime dateTime)
        {
            try
            {
                var result = new List<HistoryOrderModel>();
                var _order = await _orderRepository.GetAllAsync();
                var _user = await _userRepository.GetAllAsync();
                var _orderDetail = await _orderDetailRepository.GetAllAsync();
                _order = _order.Where(x => x.CreatedOn.Value.Date == dateTime.Date);
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

                return Json(new { success = true, result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }
        [HttpPost]
        public async Task<IActionResult> GetMonthHistoryOrder(int month)
        {
            try
            {
                var result = new List<HistoryOrderModel>();
                var _order = await _orderRepository.GetAllAsync();
                var _user = await _userRepository.GetAllAsync();
                var _orderDetail = await _orderDetailRepository.GetAllAsync();
                _order = _order.Where(x => x.CreatedOn.Value.Month == month);
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

                return Json(new { success = true, result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }
    }
}
