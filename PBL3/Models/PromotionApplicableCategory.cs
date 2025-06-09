using System.ComponentModel.DataAnnotations.Schema;
using PBL3.Models;

public class PromotionApplicableCategory
{
    // Khóa chính phức hợp sẽ được định nghĩa bằng Fluent API
    public int PromotionId { get; set; }
    [ForeignKey("PromotionId")]
    public virtual Promotion Promotion { get; set; }

    public int CategoryId { get; set; } // Category của món ăn
    [ForeignKey("CategoryId")]
    public virtual Category Category { get; set; }
}