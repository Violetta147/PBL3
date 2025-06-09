using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Http;
using PBL3.Extensions;
using PBL3.Models;
using PBL3.Extensions;

namespace PBL3.ViewModel.Restaurant
{
    public class DailyOperatingHoursInputViewModel
    {
        public DayOfWeek DayOfWeek { get; set; }

        [Display(Name = "Mở cửa")]
        public bool IsOpen { get; set; } = true; // Mặc định là mở

        // Khung giờ 1
        [Display(Name = "Mở cửa (1)")]
        [DataType(DataType.Time)]
        public string? OpenTime1 { get; set; } // Nhập dạng "HH:mm"

        [Display(Name = "Đóng cửa (1)")]
        [DataType(DataType.Time)]
        public string? CloseTime1 { get; set; }

        // Khung giờ 2 (tùy chọn)
        [Display(Name = "Mở cửa (2)")]
        [DataType(DataType.Time)]
        public string? OpenTime2 { get; set; }

        [Display(Name = "Đóng cửa (2)")]
        [DataType(DataType.Time)]
        public string? CloseTime2 { get; set; }

        [StringLength(100)]
        public string? Notes1 { get; set; }

        [StringLength(100)]
        public string? Notes2 { get; set; }
        [NotMapped]
        public string DayDisplayName => DayOfWeek.ToVietnameseDayOfWeek();
    }

    public class RegisterRestaurantViewModel
    {
        [Required(ErrorMessage = "Tên nhà hàng không được để trống.")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Tên nhà hàng phải từ 3 đến 200 ký tự.")]
        [Display(Name = "Tên nhà hàng")]
        public string Name { get; set; }

        [DataType(DataType.MultilineText)]
        [StringLength(2000, ErrorMessage = "Mô tả không được vượt quá 2000 ký tự.")]
        [Display(Name = "Mô tả")]
        public string? Description { get; set; } // Cho phép null

        [Required(ErrorMessage = "Số điện thoại không được để trống.")]
        [Phone(ErrorMessage = "Số điện thoại không hợp lệ.")]
        [StringLength(20)]
        [Display(Name = "Số điện thoại")]
        public string PhoneNumber { get; set; }

        [Url(ErrorMessage = "Địa chỉ website không hợp lệ.")]
        [StringLength(200)]
        [Display(Name = "Website (tùy chọn)")]
        public string? Website { get; set; }

        // --- THAY THẾ OpeningHours string bằng cấu trúc chi tiết ---
        [Display(Name = "Giờ hoạt động")]
        public List<DailyOperatingHoursInputViewModel> OperatingHoursList { get; set; }
        // ---------------------------------------------------------

        // --- THAY THẾ PriceRange enum bằng Min/Max Price ---
        [Display(Name = "Giá thấp nhất (ước tính/người)")]
        [Range(0, double.MaxValue, ErrorMessage = "Giá trị không hợp lệ.")]
        [Column(TypeName = "decimal(18,0)")]
        public decimal? MinTypicalPrice { get; set; }

        [Display(Name = "Giá cao nhất (ước tính/người)")]
        [Range(0, double.MaxValue, ErrorMessage = "Giá trị không hợp lệ.")]
        [Column(TypeName = "decimal(18,0)")]
        public decimal? MaxTypicalPrice { get; set; }
        // -------------------------------------------------

        [Display(Name = "Ảnh đại diện (tùy chọn)")]
        public IFormFile? MainImageFile { get; set; }

        [Display(Name = "Các ảnh khác (tùy chọn)")]
        public List<IFormFile>? OtherImageFiles { get; set; }


        // --- Thông tin Địa chỉ (Giữ nguyên như bạn đã có là ổn) ---
        [Required(ErrorMessage = "Địa chỉ chi tiết không được để trống.")]
        [StringLength(300)]
        [Display(Name = "Địa chỉ (Số nhà, tên đường)")]
        public string AddressLine1 { get; set; }

        [Required(ErrorMessage = "Phường/Xã không được để trống.")]
        [StringLength(100)]
        [Display(Name = "Phường/Xã")]
        public string Ward { get; set; }

        [Required(ErrorMessage = "Quận/Huyện không được để trống.")]
        [StringLength(100)]
        [Display(Name = "Quận/Huyện")]
        public string District { get; set; }

        [Required(ErrorMessage = "Tỉnh/Thành phố không được để trống.")]
        [StringLength(100)]
        [Display(Name = "Tỉnh/Thành phố")]
        public string City { get; set; }

        [StringLength(50)]
        [Display(Name = "Quốc gia")]
        public string Country { get; set; } = "Việt Nam";

        [Display(Name = "Vĩ độ (tùy chọn)")]
        [Range(-90, 90, ErrorMessage = "Vĩ độ không hợp lệ.")]
        public double? Latitude { get; set; }

        [Display(Name = "Kinh độ (tùy chọn)")]
        [Range(-180, 180, ErrorMessage = "Kinh độ không hợp lệ.")]
        public double? Longitude { get; set; }
        // -----------------------------------------------------


        // --- IDs cho CuisineTypes và Tags được chọn ---
        [Display(Name = "Loại hình ẩm thực")]
        public List<int> SelectedCuisineTypeIds { get; set; } = new();

        [Display(Name = "Đặc điểm/Tiện ích")]
        public List<int> SelectedTagIds { get; set; } = new();
        public List<SelectableCuisineTypeViewModel> AvailableCuisineTypes { get; set; }
        public List<SelectableTagViewModel> AvailableTags { get; set; }


        public RegisterRestaurantViewModel()
        {
            OperatingHoursList = new List<DailyOperatingHoursInputViewModel>();
            for (int i = 0; i < 7; i++) // Khởi tạo cho 7 ngày trong tuần
            {
                OperatingHoursList.Add(new DailyOperatingHoursInputViewModel { DayOfWeek = (DayOfWeek)i, IsOpen = true });
            }
            OtherImageFiles = new List<IFormFile>();
            SelectedCuisineTypeIds = new List<int>();
            SelectedTagIds = new List<int>();
            Country = "Việt Nam"; // Đảm bảo giá trị mặc định

            AvailableCuisineTypes = new List<SelectableCuisineTypeViewModel>();
            AvailableTags = new List<SelectableTagViewModel>();
        }
    }

    public class SelectableCuisineTypeViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string IconUrl { get; set; } // Nếu có
        public bool IsSelected { get; set; }
    }

    public class SelectableTagViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string IconUrl { get; set; } // Nếu có
        public bool IsSelected { get; set; }
    }

}
