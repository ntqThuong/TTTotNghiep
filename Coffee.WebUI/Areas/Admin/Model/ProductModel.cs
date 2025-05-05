using Coffee.DATA.Models;

namespace Coffee.WebUI.Areas.Admin.Model
{
    public class ProductModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
        public decimal? DiscountPrice { get; set; }
        public string Description { get; set; }
        public string DescriptionShort { get; set; }
        public string Quantity { get; set; }
        public string Keywords { get; set; }
        public string? Image { get; set; }
        public int CategoryId { get; set; }
        public bool Status { get; set; }
    }
}
