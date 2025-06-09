using System.ComponentModel.DataAnnotations.Schema;
using PBL3.Models;

public class PromotionApplicableItem
{
    // Khóa chính phức hợp sẽ được định nghĩa bằng Fluent API
    public int PromotionId { get; set; }
    [ForeignKey("PromotionId")]
    public virtual Promotion Promotion { get; set; }

    public int MenuItemId { get; set; }
    [ForeignKey("MenuItemId")]
    public virtual MenuItem MenuItem { get; set; }

    // Bạn có thể thêm các thuộc tính dành riêng cho sự kết hợp này nếu cần, ví dụ:
    // - Số lượng tối thiểu của MenuItem này để được áp dụng khuyến mãi
    // - Một giá trị giảm giá cụ thể chỉ cho MenuItem này trong Promotion này (ghi đè DiscountValue của Promotion)
    // Hiện tại, chúng ta giữ đơn giản.
}