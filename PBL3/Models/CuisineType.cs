using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public class CuisineType
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Tên loại hình ẩm thực không được để trống.")]
        [StringLength(100)]
        public string Name { get; set; } // Ví dụ: "Ẩm thực Việt Nam", "Italian Cuisine", "Vegan"

        [StringLength(500)]
        public string? Description { get; set; } // Mô tả thêm (tùy chọn)

        [StringLength(255)]
        [Url(ErrorMessage = "Đường dẫn icon không hợp lệ.")]
        public string? IconUrl { get; set; } // URL đến icon đại diện (tùy chọn)

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation property cho các Restaurant thuộc CuisineType này (Many-to-Many)
        // Tên 'Restaurants' ở đây sẽ được dùng trong Fluent API của RestaurantCuisine
        public virtual ICollection<RestaurantCuisine> Restaurants { get; set; }

        public CuisineType()
        {
            Restaurants = new HashSet<RestaurantCuisine>();
        }
    }
}
