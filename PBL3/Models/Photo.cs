using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public enum PhotoType
    {
        RestaurantGeneric, // Ảnh chung của nhà hàng (không gian, mặt tiền,...)
        ReviewAttachment,  // Ảnh do người dùng đính kèm vào review
        MenuItemImage      // Ảnh của một món ăn cụ thể trong menu
    }

    public class Photo
    {
        public int Id { get; set; }

        [Required]
        [StringLength(500)]
        public string Url { get; set; }

        [StringLength(500)]
        public string Caption { get; set; }

        public DateTime UploadedDate { get; set; } = DateTime.UtcNow;

        public PhotoType Type { get; set; }

        // --- BỎ CÁC THUỘC TÍNH LIÊN QUAN ĐẾN USER UPLOAD ---
        // public string UserId { get; set; }
        // [ForeignKey("UserId")]
        // public virtual AppUser User { get; set; }
        // --------------------------------------------------

        // Foreign Key cho Restaurant (ảnh này thuộc về nhà hàng nào?)
        public int? RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        // Foreign Key cho Review (ảnh này thuộc về đánh giá nào?)
        public int? ReviewId { get; set; }
        [ForeignKey("ReviewId")]
        public virtual Review Review { get; set; }

        // Foreign Key cho MenuItem (ảnh này thuộc về món ăn nào?)
        public int? MenuItemId { get; set; }
        [ForeignKey("MenuItemId")]
        public virtual MenuItem MenuItem { get; set; }
    }
}
