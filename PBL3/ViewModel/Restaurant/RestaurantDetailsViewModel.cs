using PBL3.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using PBL3.ViewModel.Menu;

namespace PBL3.ViewModel.Restaurant
{
    // ViewModel cho một OperatingHour để hiển thị
    public class OperatingHourViewModel
    {
        public string DayDisplayName { get; set; } // Ví dụ: "Thứ Hai", "Chủ Nhật"
        public List<string> TimeSlots { get; set; } // Ví dụ: ["09:00 - 14:00", "17:00 - 22:00"]
        public bool IsOpenToday { get; set; } // Ngày này có mở cửa không (dựa trên IsOpen và có TimeSlots)
        public string? Notes { get; set; } // Ghi chú chung cho ngày đó nếu có
    }

    // ViewModel cho một Review rút gọn
    public class ReviewSummaryViewModel
    {
        public int Id { get; set; }
        public int Rating { get; set; }
        public string? Comment { get; set; }
        public DateTime ReviewDate { get; set; }
        public string UserDisplayName { get; set; }
        public string? UserAvatarUrl { get; set; }
        public List<string> PhotoUrls { get; set; }
        public ReviewSummaryViewModel() { PhotoUrls = new List<string>(); }
    }


    public class RestaurantDetailViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string? Description { get; set; }
        public string? MainImageUrl { get; set; }
        public List<string> OtherImageUrls { get; set; } // Danh sách URL các ảnh khác của nhà hàng

        // Thông tin địa chỉ chi tiết
        public string AddressLine1 { get; set; }
        public string Ward { get; set; }
        public string District { get; set; }
        public string City { get; set; }
        public string Country { get; set; }
        public string FullAddressText { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }

        // Thông tin liên hệ
        public string? PhoneNumber { get; set; }
        public string? Website { get; set; }

        // Giờ hoạt động
        public List<OperatingHourViewModel> OperatingHoursGroupedByDay { get; set; }
        public string CurrentOverallOpeningStatusText { get; set; } // Ví dụ: "Đang mở cửa", "Sắp mở cửa", "Đã đóng cửa"
        public bool IsCurrentlyOpen { get; set; }

        // Khoảng giá
        public string PriceRangeText { get; set; } // "50.000 - 150.000 VNĐ" hoặc "$$"

        // Đánh giá
        public double AverageRating { get; set; }
        public int ReviewCount { get; set; }
        public List<ReviewSummaryViewModel> Reviews { get; set; } // Danh sách các review
        // (Có thể thêm phân tích số lượng sao: 5 sao - X lượt, 4 sao - Y lượt,...)

        // Phân loại và Đặc điểm
        public List<string> CuisineTypeNames { get; set; }
        public List<string> TagNames { get; set; }

        // Thực đơn
        public List<MenuViewModel> Menus { get; set; } // Danh sách các menu của nhà hàng

        // Thông tin chủ sở hữu (tùy chọn hiển thị)
        public string? OwnerDisplayName { get; set; }
        public string? OwnerAvatarUrl { get; set; }

        // Khuyến mãi đang áp dụng (tùy chọn)
        // public List<PromotionSummaryViewModel> ActivePromotions { get; set; }

        public RestaurantDetailViewModel()
        {
            OtherImageUrls = new List<string>();
            OperatingHoursGroupedByDay = new List<OperatingHourViewModel>();
            Reviews = new List<ReviewSummaryViewModel>();
            CuisineTypeNames = new List<string>();
            TagNames = new List<string>();
            Menus = new List<MenuViewModel>();
            // ActivePromotions = new List<PromotionSummaryViewModel>();
        }
    }
}