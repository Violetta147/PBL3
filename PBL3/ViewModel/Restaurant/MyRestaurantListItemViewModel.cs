using PBL3.Models; // Cho Enum RestaurantStatus
using System;
using System.ComponentModel.DataAnnotations; // Cho Display attribute
using PBL3.Extensions;

namespace PBL3.ViewModel.Restaurant
{
    public class MyRestaurantListItemViewModel
    {
        public int Id { get; set; }

        [Display(Name = "Tên Nhà Hàng")]
        public string Name { get; set; }

        [Display(Name = "Ảnh Đại Diện")]
        public string? MainImageUrl { get; set; }

        [Display(Name = "Địa Chỉ")]
        public string FullAddressText { get; set; } // Hiển thị địa chỉ đầy đủ hơn

        [Display(Name = "Trạng Thái")]
        public RestaurantStatus Status { get; set; } // Hiển thị trạng thái enum trực tiếp hoặc tên của nó
        public string StatusDisplayName => Status.ToVietnameseRestaurantStatus();

        [Display(Name = "Ngày Tạo")]
        [DisplayFormat(DataFormatString = "{0:dd/MM/yyyy}")]
        public DateTime CreatedAt { get; set; }

        [Display(Name = "Lượt Đánh Giá")]
        public int ReviewCount { get; set; }

        [Display(Name = "Điểm Trung Bình")]
        [DisplayFormat(DataFormatString = "{0:N1}")] // Format số có 1 chữ số thập phân
        public double AverageRating { get; set; }

        // Các URL cho hành động (sẽ được tạo trong Service hoặc Controller)
        public string ViewDetailsUrl { get; set; }
        public string EditRestaurantUrl { get; set; }
        public string ManageMenuUrl { get; set; }
    }
}
