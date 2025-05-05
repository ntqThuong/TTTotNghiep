namespace Coffee.WebUI.Models
{
    public class NewModel
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        public string Description { get; set; }
        public string Keywords { get; set; }
        public string Url { get; set; }
        public string Image { get; set; }
        public int UserId { get; set; }
        public string UserName { get; set; }
        public DateTime CreatedOn { get; set; }
        public bool Status { get; set; }
    }
}
