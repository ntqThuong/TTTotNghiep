using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Coffee.DATA.Models
{
    public class New : BaseEntities
    {
        public string? Title { get; set; }
        public string? Content { get; set; }
        public string? Description { get; set; }
        public string? Url { get; set; }
        public string? Keywords { get; set; }
        public string? Image { get; set; }
        public int? UserId { get; set; }
        public virtual User? User { get; set; }
    }
}
