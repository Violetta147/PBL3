using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class MenuSection
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string Title { get; set; } // Ví dụ: "Khai vị", "Món chính", "Combo đặc biệt"

        [StringLength(500)]
        public string? Description { get; set; } // Mô tả thêm cho section này (tùy chọn)

        public int DisplayOrder { get; set; } // Thứ tự hiển thị các section trong một menu

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Foreign Key đến Menu
        [Required]
        public int MenuId { get; set; }
        [ForeignKey("MenuId")]
        public virtual Menu Menu { get; set; }

        // Navigation property cho các MenuItem thuộc Section này
        public virtual ICollection<MenuItem> MenuItems { get; set; }

        public MenuSection()
        {
            MenuItems = new HashSet<MenuItem>();
        }
    }
}
