namespace Coffee.WebUI.Areas.Admin.Model
{
    public class HistoryOrderModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public DateTime FinishDay { get; set; }
        public decimal Total { get; set; }
        public bool PayStatus { get; set; }
        public bool OrderStatus { get; set; }
        public string StaffName { get; set; }
    }
}
