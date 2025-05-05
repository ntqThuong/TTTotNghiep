using Coffee.DATA.Models;

namespace Coffee.WebUI.Models
{
    public class ReviewModel
    {
        public int Id { get; set; }
        public string ContentReview { get; set; }
        public int Rating { get; set; }
        public int UserId { get; set; }
        public string UserName { get; set; }
        public int ProductId { get; set; }
        public bool Status { get; set; }
        public DateTime CreatedOn { get; set; }
    }
}
