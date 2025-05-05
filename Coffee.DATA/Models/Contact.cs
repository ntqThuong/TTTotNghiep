using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Coffee.DATA.Models
{
    public class Contact :BaseEntities
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
    }
}
