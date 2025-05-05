using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Coffee.DATA.Models
{
    public class Book : BaseEntities
    {
        public string Name { get; set; }
        public string Phone { get; set; }
        public string Seates { get; set; }
        public string Email { get; set; }
        public DateTime Day { get; set; }
        public TimeSpan Time { get; set; }
    }
}
