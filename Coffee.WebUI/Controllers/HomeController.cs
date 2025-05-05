using Coffee.WebUI.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using Coffee.DATA;
using Coffee.DATA.Models;
using System.Net.Mail;
using Microsoft.AspNetCore.SignalR;
using Coffee.DATA.Service;
using Coffee.DATA.Repository;

namespace Coffee.WebUI.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IHubContext<NotificationHub> _hubContext;
        private readonly IRepository<Book> _bookRepository;
        private readonly IRepository<Contact> _contactRepository;
        private readonly IRepository<Product> _productRepository;

        public HomeController(IRepository<Product> productRepository, ILogger<HomeController> logger, IHubContext<NotificationHub> hubContext, IRepository<Contact> contactRepository, IRepository<Book> bookRepository)
        {
            _productRepository = productRepository;
            _logger = logger;
            _hubContext = hubContext;
            _contactRepository = contactRepository;
            _bookRepository = bookRepository;
        }
        public async Task<IActionResult> Index()
        {
            var _product = await _productRepository.GetAllAsync();
            _product = _product.Where(x => x.DiscountPrice > 0 && x.Status == true);

            var _proDiscount = _product.OrderBy(x => Guid.NewGuid()).Take(6).ToList();
            ViewBag.ProductDiscount = _proDiscount;
            return View();
        }
        public IActionResult Introduce()
        {
            return View();
        }
        public IActionResult Contact()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Contact(Contact model)
        {
            if (ModelState.IsValid)
            {
                var _contact = new Contact
                {
                    Name = model.Name,
                    Email = model.Email,
                    Title = model.Title,
                    Content = model.Content,
                    CreatedOn = DateTime.Now,
                    Status = true,
                };
                await _contactRepository.InsertAsync(_contact);
                ViewBag.Success = "Cảm ơn quý khách đã gữi liên hệ!";
            }
            return View();
        }
        public IActionResult Reservation()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Reservation(Book model)
        {
            try
            {
                var _book = new Book
                {
                    Name = model.Name,
                    Email = model.Email,
                    Phone = model.Phone,
                    Day = model.Day,
                    Time = model.Time,
                    Seates = model.Seates,
                    Status = false,
                };
                await _bookRepository.InsertAsync(_book);
                ViewBag.Success = "Cảm ơn quý khách đã đặt bàn. Vui lòng check lại email để lấy thông tin đặt bàn!";
                // Mật khẩu ứng dụng OtpEmail : kemz hkfu jode ctfp

                MailMessage message = new MailMessage("txvq0101@gmail.com", model.Email, "Thông tin đặt bàn", "Cảm ơn quý khách đã đặt bàn chúng tôi sẽ liên hệ lại sau!");
                SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
                client.EnableSsl = true;
                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                client.UseDefaultCredentials = false;
                client.Credentials = new System.Net.NetworkCredential("txvq0101@gmail.com", "kemz hkfu jode ctfp");
                client.Send(message);
                await _hubContext.Clients.All.SendAsync("ReceiveMessage");
            }
            catch (Exception ex)
            {
                return View(ex);
            }
            return View();

        }
        public IActionResult Error()
        {
            return View();
        }
    }
}
