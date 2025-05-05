using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Coffee.DATA.Models
{
    public class Order : BaseEntities
    {
        public int? UserId { get; set; }
        public DateTime? CreateOn { get; set; }
        public string? Province { get; set; }
        public string? District { get; set; }
        public string? Town { get; set; }
        public string? Address { get; set; }
        public bool? Status { get; set; }
        public int? StaffId { get; set; }
        public bool? OrderStatus { get; set; }
        public string? InvoiceNumber { get; set; } //vnp_TxnRef Số hoá đơn
        public string? TradingCode { get; set; } //vnp_TransactionNo Mã giao dịch tại VnPay
        public virtual ICollection<OrderDetail> OrderDetails { get; set; } = new List<OrderDetail>();
        public User User { get; set; }
    }
}
