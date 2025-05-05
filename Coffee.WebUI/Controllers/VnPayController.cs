using Coffee.WebUI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using log4net;
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Coffee.DATA.Common;
using Coffee.DATA.Models;
using System.Security.Claims;
using Coffee.DATA;
using Microsoft.EntityFrameworkCore;
using System.Net;
using Microsoft.AspNetCore.SignalR;
using Coffee.DATA.Service;
using Coffee.DATA.Repository;

namespace Coffee.WebUI.Controllers
{
    public class VnPayController : Controller
    {
        private readonly IConfiguration _configuration;
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly DbCoffeeDbContext _db;
        private readonly IHubContext<NotificationHub> _hubContext;
        private readonly IRepository<User> _userRepository;
        private readonly IRepository<Order> _orderRepository;
        private readonly IRepository<OrderDetail> _orderDetailRepository;

        public VnPayController(IRepository<User> userRepository, IRepository<Order> orderRepository, IRepository<OrderDetail> orderDetailRepository, IConfiguration configuration, IHttpContextAccessor httpContextAccessor, DbCoffeeDbContext db, IHubContext<NotificationHub> hubContext)
        {
            _userRepository = userRepository;
            _orderRepository = orderRepository;
            _orderDetailRepository = orderDetailRepository;
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
            _db = db;
            _hubContext = hubContext;
        }

        public async Task<IActionResult> Index(string Province, string District, string Town, string Address)
        {
            if (Province == "" || District == "" || Town == "" || Address == "")
            {
                return StatusCode(404);
            }
            else
            {
                HttpContext.Session.SetString("Province", Province);
                HttpContext.Session.SetString("District", District);
                HttpContext.Session.SetString("Town", Town);
                HttpContext.Session.SetString("Address", Address);
            }
            string vnp_Returnurl = _configuration["Vnpay:vnp_Returnurl"];
            string vnp_Url = _configuration["Vnpay:vnp_Url"];
            string vnp_TmnCode = _configuration["Vnpay:vnp_TmnCode"];
            string vnp_HashSecret = _configuration["Vnpay:vnp_HashSecret"];

            var httpContext = _httpContextAccessor.HttpContext;
            var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
            Int64 totalPrice = (Int64)CartModels.Sum(item => item.ProductModel.Price * item.Quantity);
            //int CartCount = CartModels.Sum(item => item.Quantity);

            OrderInfo order = new OrderInfo
            {
                OrderId = DateTime.Now.Ticks,
                Amount = Convert.ToInt64(totalPrice),
                Status = "0",
                CreatedDate = DateTime.Now
            };

            VnPayLibrary vnpay = new VnPayLibrary();

            vnpay.AddRequestData("vnp_Version", VnPayLibrary.VERSION);
            vnpay.AddRequestData("vnp_Command", "pay");
            vnpay.AddRequestData("vnp_TmnCode", vnp_TmnCode);
            vnpay.AddRequestData("vnp_Amount", (order.Amount * 100).ToString());
            vnpay.AddRequestData("vnp_CreateDate", order.CreatedDate.ToString("yyyyMMddHHmmss"));
            vnpay.AddRequestData("vnp_CurrCode", "VND");
            vnpay.AddRequestData("vnp_IpAddr", Utils.GetIpAddress(HttpContext));
            vnpay.AddRequestData("vnp_OrderInfo", "Thanh toan don hang:" + order.OrderId);
            vnpay.AddRequestData("vnp_OrderType", "other");
            vnpay.AddRequestData("vnp_ReturnUrl", vnp_Returnurl);
            vnpay.AddRequestData("vnp_TxnRef", order.OrderId.ToString());
            vnpay.AddRequestData("vnp_Locale", "vn");

            string paymentUrl = await Task.Run(() => vnpay.CreateRequestUrl(vnp_Url, vnp_HashSecret)); // Thực hiện tạo URL thanh toán bất đồng bộ
            log.InfoFormat("VNPAY URL: {0}", paymentUrl);
            return Redirect(paymentUrl);
        }
        public async Task<IActionResult> ConfirmPay([FromQuery] ConfirmPayViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (model.vnp_ResponseCode == "00" && model.vnp_TransactionStatus == "00")
                {
                    var httpContext = _httpContextAccessor.HttpContext;
                    var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
                    var _emailUser = User.FindFirst(ClaimTypes.Email)?.Value;
                    var _user = await _userRepository.GetAllAsync();
                    var _userId = _user.First(x => x.Email.Contains(_emailUser));
                    var _order = new Order
                    {
                        UserId = _userId.Id,
                        CreatedOn = DateTime.Now,
                        Status = true,
                        OrderStatus = false,
                        InvoiceNumber = model.vnp_TxnRef,
                        TradingCode = model.vnp_TransactionNo,
                        Province = HttpContext.Session.GetString("Province"),
                        District = HttpContext.Session.GetString("District"),
                        Town = HttpContext.Session.GetString("Town"),
                        Address = HttpContext.Session.GetString("Address")
                    };
                    var _orederId = await _orderRepository.InsertAsync(_order);
                    foreach (var item in CartModels)
                    {
                        var _orderDetail = new OrderDetail
                        {
                            OrderId = _orederId.Id,
                            ProductId = item.ProductModel.ProductId,
                            Price = item.ProductModel.Price,
                            Quanlity = item.Quantity,
                        };
                        await _orderDetailRepository.InsertAsync(_orderDetail);
                    }
                    ViewBag.ResponseCode = "00";
                    HttpContext.Session.Remove("Province");
                    HttpContext.Session.Remove("District");
                    HttpContext.Session.Remove("Town");
                    HttpContext.Session.Remove("Address");
                    HttpContext.Session.Remove("Cart");
                    await _hubContext.Clients.All.SendAsync("OrderHub");
                    return RedirectToAction("Index", "HistoryOrder");
                }
                else
                {
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "07" ? "Trừ tiền thành công. Giao dịch bị nghi ngờ (liên quan tới lừa đảo, giao dịch bất thường)." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "09" ? "Giao dịch không thành công do: Thẻ/Tài khoản của khách hàng chưa đăng ký dịch vụ InternetBanking tại ngân hàng." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "10" ? "Giao dịch không thành công do: Khách hàng xác thực thông tin thẻ/tài khoản không đúng quá 3 lần" : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "11" ? "Giao dịch không thành công do: Đã hết hạn chờ thanh toán. Xin quý khách vui lòng thực hiện lại giao dịch." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "12" ? "Giao dịch không thành công do: Thẻ/Tài khoản của khách hàng bị khóa." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "13" ? "Giao dịch không thành công do Quý khách nhập sai mật khẩu xác thực giao dịch (OTP). Xin quý khách vui lòng thực hiện lại giao dịch." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "24" ? "Giao dịch không thành công do: Khách hàng hủy giao dịch" : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "51" ? "Giao dịch không thành công do: Tài khoản của quý khách không đủ số dư để thực hiện giao dịch." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "65" ? "Giao dịch không thành công do: Tài khoản của Quý khách đã vượt quá hạn mức giao dịch trong ngày." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "75" ? "Ngân hàng thanh toán đang bảo trì." : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "79" ? "Giao dịch không thành công do: KH nhập sai mật khẩu thanh toán quá số lần quy định. Xin quý khách vui lòng thực hiện lại giao dịch" : null;
                    ViewBag.ResponseCode = model.vnp_ResponseCode == "99" ? "Có lỗi vui lòng liên hệ với Admin" : null;
                    return View();
                }
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
        [HttpPost]
        public async Task<IActionResult> PayCod(string Province, string District, string Town, string Address)
        {
            if (Province == "" || District == "" || Town == "" || Address == "")
            {
                return StatusCode(404);
            }
            var httpContext = _httpContextAccessor.HttpContext;
            var CartModels = httpContext.Session.Get<List<CartModel>>("Cart") ?? new List<CartModel>();
            var _emailUser = User.FindFirst(ClaimTypes.Email)?.Value;
            var _userId = await _db.Users.FirstAsync(x => x.Email.Contains(_emailUser));
            var _order = new Order
            {
                UserId = _userId.Id,
                CreatedOn = DateTime.Now,
                Status = false,
                OrderStatus = false,
                InvoiceNumber = "0",
                TradingCode = "0",
                Province = Province,
                District = District,
                Town = Town,
                Address = Address
            };
            var _orederId = await _orderRepository.InsertAsync(_order);
            foreach (var item in CartModels)
            {
                var _orderDetail = new OrderDetail
                {
                    OrderId = _orederId.Id,
                    ProductId = item.ProductModel.ProductId,
                    Price = item.ProductModel.Price,
                    Quanlity = item.Quantity,
                };
                await _orderDetailRepository.InsertAsync(_orderDetail);
            }
            HttpContext.Session.Remove("Cart");
            await _hubContext.Clients.All.SendAsync("OrderHub");
            return RedirectToAction("Index", "HistoryOrder");
        }
    }
}
