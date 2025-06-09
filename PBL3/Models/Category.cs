using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class Category
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string Name { get; set; } // Ví dụ: "Món Việt", "Món Ý", "Hải sản", "Đồ chay"

        [StringLength(500)]
        public string? Description { get; set; } // Mô tả thêm (tùy chọn)

        public string IconUrl { get; set; } // URL đến icon đại diện cho category (tùy chọn)

        // Nếu bạn muốn có cấu trúc cha-con cho Category (ví dụ: "Món Á" -> "Món Việt", "Món Nhật")
        public int? ParentCategoryId { get; set; }
        [ForeignKey("ParentCategoryId")]
        public virtual Category ParentCategory { get; set; }
        public virtual ICollection<Category> ChildCategories { get; set; }


        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation property cho các MenuItem thuộc Category này (Many-to-Many)
        public virtual ICollection<MenuItemCategory> MenuItemCategories { get; set; }
        public virtual ICollection<PromotionApplicableCategory> PromotionsAppliedToThisCategory { get; set; }
        public Category()
        {
            ChildCategories = new HashSet<Category>();
            MenuItemCategories = new HashSet<MenuItemCategory>();
            PromotionsAppliedToThisCategory = new HashSet<PromotionApplicableCategory>();
            CreatedAt = System.DateTime.UtcNow;
            UpdatedAt = System.DateTime.UtcNow;
        }
    }
}
