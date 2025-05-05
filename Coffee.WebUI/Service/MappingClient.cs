using AutoMapper;
using Coffee.DATA.Models;
using Coffee.WebUI.Models;

namespace Coffee.WebUI.Service
{
    public class MappingClient: Profile
    {
        public MappingClient()
        {
            CreateMap<Review,ReviewModel>();
            CreateMap<New,NewModel>();
        }
    }
}
