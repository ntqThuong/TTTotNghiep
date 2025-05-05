namespace Coffee.WebUI.Areas.Admin.Model
{
    public class UserOrder
    {
        public int OrderId { get; set; }
        public int UserId { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public string Province { get; set; }
        public string District { get; set; }
        public string Town { get; set; }
        public decimal Total { get; set; }
        public bool Status { get; set; }
        public bool OrderStatus { get; set; }
    }
}
