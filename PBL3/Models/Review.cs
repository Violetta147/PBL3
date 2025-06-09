using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class Review
    {
        public int Id { get; set; } // Hoặc Guid Id { get; set; }

        [Required(ErrorMessage = "Vui lòng chọn số sao đánh giá.")]
        [Range(1, 5, ErrorMessage = "Số sao đánh giá phải từ 1 đến 5.")]
        public int Rating { get; set; }

        [StringLength(2000, ErrorMessage = "Nội dung bình luận không được vượt quá 2000 ký tự.")]
        public string Comment { get; set; }

        public DateTime ReviewDate { get; set; } = DateTime.UtcNow;

        // Foreign Key cho User (người viết review)
        [Required]
        public string UserId { get; set; } // Kiểu dữ liệu của khóa chính trong AppUser (thường là string)
        [ForeignKey("UserId")]
        public virtual AppUser User { get; set; } // Sử dụng AppUser như bạn đã chỉ định

        // Foreign Key cho Restaurant (nhà hàng được review)
        [Required]
        public int RestaurantId { get; set; } // Hoặc Guid RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        // Navigation Property cho hình ảnh đính kèm review (nếu có)
        public virtual ICollection<ReviewPhoto> Photos { get; set; }

        public Review()
        {
            Photos = new HashSet<ReviewPhoto>();
            ReviewDate = DateTime.UtcNow;
        }
    }
}
