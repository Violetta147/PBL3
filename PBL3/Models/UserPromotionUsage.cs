using System;
using System.ComponentModel.DataAnnotations.Schema;
using PBL3.Models;

public class UserPromotionUsage
{
    // Khóa chính phức hợp sẽ được định nghĩa bằng Fluent API
    [ForeignKey("User")] // Đặt tên cho FK rõ ràng hơn nếu cần
    public string UserId { get; set; }
    public virtual AppUser User { get; set; }

    [ForeignKey("Promotion")] // Đặt tên cho FK rõ ràng hơn nếu cần
    public int PromotionId { get; set; }
    public virtual Promotion Promotion { get; set; }

    public int UsageCount { get; set; } = 0; // Số lần người dùng này đã sử dụng khuyến mãi này

    public DateTime LastUsedDate { get; set; } // Lần cuối cùng người dùng này sử dụng khuyến mãi này
}