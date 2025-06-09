using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public class Tag
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string Name { get; set; } // Ví dụ: "Wifi miễn phí", "Có chỗ đậu xe", "View đẹp"

        public string? IconUrl { get; set; }
        [StringLength(200)]
        public string? Description { get; set; } // Mô tả thêm (tùy chọn)

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation property cho các Restaurant có Tag này (Many-to-Many)
        // Tên 'RestaurantTags' ở đây sẽ được dùng trong Fluent API của RestaurantTag
        public virtual ICollection<RestaurantTag> RestaurantTags { get; set; }

        public Tag()
        {
            RestaurantTags = new HashSet<RestaurantTag>();
        }
    }
}
