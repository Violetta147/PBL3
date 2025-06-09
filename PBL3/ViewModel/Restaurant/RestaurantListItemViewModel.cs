using PBL3.Models; // Cho Enum RestaurantStatus
using System;
using System.Collections.Generic;

namespace PBL3.ViewModel.Restaurant
{
    public class RestaurantListItemViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string? MainImageUrl { get; set; } // URL ảnh đại diện
        public double AverageRating { get; set; }
        public int ReviewCount { get; set; }

        // Thông tin rút gọn về địa chỉ
        public string? ShortAddress { get; set; } // Ví dụ: "Quận 1, TP. HCM" hoặc "Phường Bến Nghé, Quận 1"

        // Danh sách tên các loại hình ẩm thực (chỉ tên)
        public List<string> CuisineTypeNames { get; set; }

        // Danh sách tên các tag (chỉ tên)
        public List<string> TagNames { get; set; }

        // Khoảng giá dưới dạng text
        public string PriceRangeText { get; set; } // Ví dụ: "50.000 - 150.000 VNĐ" hoặc "$$"

        // Thông tin về trạng thái mở cửa hiện tại
        public bool IsCurrentlyOpen { get; set; }
        public string CurrentOpeningStatusText { get; set; } // Ví dụ: "Đang mở cửa - Đóng lúc 22:00", "Đã đóng cửa", "Mở cửa lúc 09:00"

        // (Tùy chọn) Nếu có tìm kiếm theo khoảng cách
        // public string? DistanceText { get; set; } // Ví dụ: "Cách bạn 1.2 km"

        public RestaurantListItemViewModel()
        {
            CuisineTypeNames = new List<string>();
            TagNames = new List<string>();
            PriceRangeText = "Chưa cập nhật"; // Giá trị mặc định
            CurrentOpeningStatusText = "Chưa rõ"; // Giá trị mặc định
        }
    }
}
