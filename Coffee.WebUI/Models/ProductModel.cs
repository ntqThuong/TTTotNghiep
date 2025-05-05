namespace Coffee.WebUI.Models
{
    public class ProductModel
    {
        public int? ProductId { get; set; }
        public string? Name { get; set; }
        public string? Image { get; set; }
        public string? Url { get; set; }
        public string? Description { get; set; }
        public string? DescriptionShort { get; set; }
        public string? Quantity { get; set; }
        public string? Keywords { get; set; }
        public decimal? Price { get; set; }
        public decimal? DiscountPrice { get; set; }
        public int? categoryId { get; set; }
        public string? categoryName { get; set; }
        public List<ProductImageModel>? ProductImages { get; set; }
    }
}
