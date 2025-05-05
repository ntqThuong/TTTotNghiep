using AutoMapper;
using Coffee.DATA.Models;
using Coffee.WebUI.Areas.Admin.Model;

namespace Coffee.WebUI.Service
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Product, ProductModel>();
            CreateMap<Category, CategoryModel>();
            CreateMap<New, NewModel>();
            CreateMap<User, AccountUserModel>();
            CreateMap<ProductImage, ProductImageModel>()
                .ForMember(dest => dest.Image, opt => opt.MapFrom(src => src.UrlImage));
        }
    }
}
