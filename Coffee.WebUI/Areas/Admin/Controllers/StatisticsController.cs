using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Coffee.WebUI.Areas.Admin.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class StatisticsController : Controller
    {
        private readonly IRepository<Order> _orderRepository;
        private readonly IRepository<OrderDetail> _orderDetailRepository;
        public StatisticsController(IRepository<Order> orderRepository, IRepository<OrderDetail> orderDetailRepository)
        {
            _orderRepository = orderRepository;
            _orderDetailRepository = orderDetailRepository;
        }
        public IActionResult Index()
        {
            return View();
        }
        public async Task<IActionResult> GetStatisticsYear()
        {
            try
            {
                var _order = await _orderRepository.GetAllAsync();
                var statisticsYear = new List<StatisticsYearModel>();
                var _orderDetail = await _orderDetailRepository.GetAllAsync();

                _order = _order.Where(x => x.CreatedOn.Value.Year == DateTime.Now.Year && x.OrderStatus == true);

                for (int i = 1; i <= 12; i++)
                {
                    var _orderListIdMonth = _order.Where(x => x.CreatedOn.Value.Month == i);
                    if (_orderListIdMonth.Count() > 0)
                    {
                        decimal _total = 0;
                        foreach (var item in _orderListIdMonth)
                        {
                            _total += Convert.ToDecimal(_orderDetail.Where(x => x.OrderId == Convert.ToInt32(item.Id)).Sum(x => x.Price));
                        }
                        statisticsYear.Add(new StatisticsYearModel
                        {
                            Months = i,
                            Total = _total
                        });
                    }
                    else
                    {
                        statisticsYear.Add(new StatisticsYearModel
                        {
                            Months = i,
                            Total = 0,
                        });
                    }
                }
                return Json(new { success = true, statisticsYear });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex.Message });
            }
        }
    }
}
