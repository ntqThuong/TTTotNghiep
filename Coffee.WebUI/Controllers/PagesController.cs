using AutoMapper;
using Coffee.DATA.Models;
using Coffee.DATA.Repository;
using Coffee.WebUI.Models;
using Microsoft.AspNetCore.Mvc;
using X.PagedList;

namespace Coffee.WebUI.Controllers
{
    public class PagesController : Controller
    {
        private readonly IRepository<New> _newRepository;
        private readonly IRepository<User> _userRepository;
        private readonly IMapper _mapper;
        public PagesController(IRepository<New> newRepository, IRepository<User> userRepository, IMapper mapper)
        {
            _newRepository = newRepository;
            _userRepository = userRepository;
            _mapper = mapper;
        }
        public IActionResult Index()
        {
            return View();
        }
        [Route("bai-viet")]
        //[Route("Blog")]
        public async Task<IActionResult> Blog(int? page)
        {
            int pageSize = 2;
            int pageNumber = page ?? 1;
            var _new = await _newRepository.GetAllAsync();
            var _user = await _userRepository.GetAllAsync();
            var result = _mapper.Map<List<NewModel>>(_new);
            foreach (var item in result)
            {
                item.UserName = _user.First(x => x.Id == item.UserId).Name;
            }
            var _result = result.AsQueryable().ToPagedList(pageNumber, pageSize);
            return View(_result);
        }
        [Route("bai-viet/{url}-{id}")]
        public async Task<IActionResult> BlogDetail(int Id)
        {
            var _new = await _newRepository.GetByIdAsync(Id);
            if(_new == null)
            {
                return StatusCode(404);
            }
            return View(_new);
        }
        [Route("nhan-vien")]
        public IActionResult Staff()
        {
            return View();
        }
        [Route("faq")]
        public IActionResult FAQ()
        {
            return View();
        }
        [Route("cau-chuyen")]
        public IActionResult Story()
        {
            return View();
        }
        [Route("trung-bay")]
        public IActionResult Gallery()
        {
            return View();
        }
    }
}
