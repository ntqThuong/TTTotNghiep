using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Coffee.DATA.Models
{
    public class Product : BaseEntities
    {
        public string? Name { get; set; }
        public decimal? Price { get; set; }
        public decimal? DiscountPrice { get; set; }
        public string? Url { get; set; }
        public string? Description { get; set; }
        public string? DescriptionShort { get; set; }
        public string? Quantity { get; set; }
        public string? Keywords { get; set; }
        public string? Image { get; set; }
        public int? CategoryId { get; set; }
        public Category? Category { get; set; }
        public ICollection<OrderDetail>? OrderDetails { get; set; } = new List<OrderDetail>();
        public ICollection<ProductImage>? ProductImages { get; set; } = new List<ProductImage>();
        public ICollection<Review> Reviews { get; set; } = new List<Review>();
    }
}
