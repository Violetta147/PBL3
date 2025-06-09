using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class Menu
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string Title { get; set; } // Ví dụ: "Thực đơn chính", "Menu trưa văn phòng"

        [StringLength(500)]
        public string Description { get; set; }

        public bool IsActive { get; set; } = true; // Menu này có đang được sử dụng không?

        public int DisplayOrder { get; set; } = 0; // Thứ tự hiển thị nếu nhà hàng có nhiều menu (mặc định là 0)

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Foreign Key đến Restaurant
        [Required]
        public int RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        // Navigation property cho các MenuSection thuộc Menu này
        public virtual ICollection<MenuSection> MenuSections { get; set; }

        public Menu()
        {
            MenuSections = new HashSet<MenuSection>();
        }
    }
}
