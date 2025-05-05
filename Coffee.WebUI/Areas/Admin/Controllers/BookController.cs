using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Coffee.DATA.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using NuGet.Protocol.Core.Types;
using System.Net.Mail;

namespace Coffee.WebUI.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class BookController : Controller
    {
        private readonly IRepository<Book> _bookingRepository;
        private readonly IHubContext<NotificationHub> _hubContext;
        public BookController(IRepository<Book> bookingRepository, IHubContext<NotificationHub> hubContext)
        {
            _bookingRepository = bookingRepository;
            _hubContext = hubContext;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Index(int Id)
        {
            try
            {
                var _book = await _bookingRepository.GetByIdAsync(Id);
                if (_book == null)
                {
                    return StatusCode(404);
                }
                else
                {
                    // Mật khẩu ứng dụng OtpEmail : kemz hkfu jode ctfp
                    string _message = "Cảm ơn quý khách đã đặt bàn. Vui lòng đến đúng " + Convert.ToString(_book.Time) + " ngày "+ Convert.ToDateTime(_book.Day).ToString("dd/MM/yyyy");
                    MailMessage message = new MailMessage("txvq0101@gmail.com", _book.Email, "Xác nhận đơn đặt bàn", _message);
                    SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
                    client.EnableSsl = true;
                    client.DeliveryMethod = SmtpDeliveryMethod.Network;
                    client.UseDefaultCredentials = false;
                    client.Credentials = new System.Net.NetworkCredential("txvq0101@gmail.com", "kemz hkfu jode ctfp");
                    client.Send(message);

                    _book.Status = true;
                    await _bookingRepository.UpdateAsync(_book);
                }
                return Json(new { success = true, message = "Duyệt thành công và gữi email xác nhận tới khách hàng!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
        public async Task<IActionResult> GetAllBook()
        {
            try
            {
                var result = await _bookingRepository.GetAllAsync();
                result = result.OrderByDescending(x => x.Id);
                return Json(new { success = true, result });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Fail: " + ex });
            }
        }
    }
}
