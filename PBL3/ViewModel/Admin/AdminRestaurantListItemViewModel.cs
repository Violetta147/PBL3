// Trong thư mục ViewModels/Admin/ (hoặc một namespace phù hợp)
// Tạo file AdminRestaurantListItemViewModel.cs
using PBL3.Models; // Cho Enum RestaurantStatus
using System;
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel.Admin
{
    public class AdminRestaurantListItemViewModel
    {
        public int Id { get; set; }

        [Display(Name = "Tên Nhà Hàng")]
        public string Name { get; set; }

        [Display(Name = "Chủ sở hữu")]
        public string? OwnerDisplayName { get; set; } // Tên hiển thị của chủ sở hữu
        public string? OwnerEmail { get; set; } // Email của chủ sở hữu

        [Display(Name = "Địa Chỉ")]
        public string FullAddressText { get; set; }

        [Display(Name = "Trạng Thái")]
        public RestaurantStatus Status { get; set; }
        // public string StatusDisplayName => Status.ToVietnameseRestaurantStatus(); // Có thể thêm nếu cần

        [Display(Name = "Ngày Tạo")]
        [DisplayFormat(DataFormatString = "{0:dd/MM/yyyy HH:mm}")]
        public DateTime CreatedAt { get; set; }

        [Display(Name = "Cập nhật lần cuối")]
        [DisplayFormat(DataFormatString = "{0:dd/MM/yyyy HH:mm}")]
        public DateTime UpdatedAt { get; set; }

        [Display(Name = "Đánh giá TB")]
        [DisplayFormat(DataFormatString = "{0:N1}")]
        public double AverageRating { get; set; }

        [Display(Name = "Lượt ĐG")]
        public int ReviewCount { get; set; }

        [Display(Name = "Ảnh Đại Diện")]
        public string? MainImageUrl { get; set; }

        // Các URL cho hành động (sẽ được tạo trong Service hoặc Controller)
        public string ViewDetailsUrl { get; set; }
        public string EditRestaurantUrl { get; set; } // Admin có thể sửa bất kỳ nhà hàng nào
        // Các URL cho Approve, Reject, Suspend, Unsuspend sẽ là các form POST
    }
}