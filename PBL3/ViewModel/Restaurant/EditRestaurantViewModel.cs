using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using PBL3.Models;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.ViewModel.Restaurant
{
    public class EditRestaurantViewModel
    {
        [Required]
        public int Id { get; set; } // ID của nhà hàng đang sửa

        [Required(ErrorMessage = "Tên nhà hàng không được để trống.")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Tên nhà hàng phải từ 3 đến 200 ký tự.")]
        [Display(Name = "Tên nhà hàng")]
        public string Name { get; set; }

        [DataType(DataType.MultilineText)]
        [StringLength(2000, ErrorMessage = "Mô tả không được vượt quá 2000 ký tự.")]
        [Display(Name = "Mô tả")]
        public string? Description { get; set; }

        [Required(ErrorMessage = "Số điện thoại không được để trống.")]
        [Phone(ErrorMessage = "Số điện thoại không hợp lệ.")]
        [StringLength(20)]
        [Display(Name = "Số điện thoại")]
        public string PhoneNumber { get; set; }

        [Url(ErrorMessage = "Địa chỉ website không hợp lệ.")]
        [StringLength(200)]
        [Display(Name = "Website (tùy chọn)")]
        public string? Website { get; set; }

        [Display(Name = "Giờ hoạt động")]
        public List<DailyOperatingHoursInputViewModel> OperatingHoursList { get; set; }

        [Display(Name = "Giá thấp nhất (ước tính/người)")]
        [Range(0, double.MaxValue, ErrorMessage = "Giá trị không hợp lệ.")]
        [Column(TypeName = "decimal(18,0)")]
        public decimal? MinTypicalPrice { get; set; }

        [Display(Name = "Giá cao nhất (ước tính/người)")]
        [Range(0, double.MaxValue, ErrorMessage = "Giá trị không hợp lệ.")]
        [Column(TypeName = "decimal(18,0)")]
        public decimal? MaxTypicalPrice { get; set; }

        // Ảnh
        [Display(Name = "Ảnh đại diện hiện tại")]
        public string? CurrentMainImageUrl { get; set; } // Để hiển thị
        public string? CurrentMainImagePublicId { get; set; } // Để xóa nếu có ảnh mới

        [Display(Name = "Tải lên ảnh đại diện mới (nếu muốn thay đổi)")]
        public IFormFile? NewMainImageFile { get; set; }

        // Quản lý các ảnh khác
        public List<RestaurantPhotoViewModel> CurrentOtherImages { get; set; } // Hiển thị các ảnh hiện có
        // RestaurantPhotoViewModel sẽ chứa Id, Url, CloudinaryPublicId, có thể thêm cờ IsDeleted
        // để người dùng đánh dấu xóa khi submit form.

        [Display(Name = "Tải lên các ảnh khác mới")]
        public List<IFormFile>? NewOtherImageFiles { get; set; }


        // Địa chỉ
        [Required]
        public int AddressId { get; set; } // ID của Address entity liên quan

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

        // CuisineTypes và Tags
        [Display(Name = "Loại hình ẩm thực")]
        public List<int> SelectedCuisineTypeIds { get; set; }

        [Display(Name = "Đặc điểm/Tiện ích")]
        public List<int> SelectedTagIds { get; set; }

        // Dùng để đổ dữ liệu lên form cho người dùng chọn
        public List<SelectableCuisineTypeViewModel> AvailableCuisineTypes { get; set; }
        public List<SelectableTagViewModel> AvailableTags { get; set; }


        public EditRestaurantViewModel()
        {
            OperatingHoursList = new List<DailyOperatingHoursInputViewModel>();
            for (int i = 0; i < 7; i++)
            {
                OperatingHoursList.Add(new DailyOperatingHoursInputViewModel { DayOfWeek = (DayOfWeek)i });
            }
            CurrentOtherImages = new List<RestaurantPhotoViewModel>();
            NewOtherImageFiles = new List<IFormFile>();
            SelectedCuisineTypeIds = new List<int>();
            SelectedTagIds = new List<int>();
            Country = "Việt Nam";
            AvailableCuisineTypes = new List<SelectableCuisineTypeViewModel>();
            AvailableTags = new List<SelectableTagViewModel>();
        }
    }

    // ViewModel con để hiển thị và quản lý ảnh hiện có trong form Edit
    public class RestaurantPhotoViewModel
    {
        public int Id { get; set; } // Id của RestaurantPhoto
        public string Url { get; set; }
        public string CloudinaryPublicId { get; set; }
        public bool IsMarkedForDeletion { get; set; } // Người dùng tick vào để xóa ảnh này
        public bool IsCover { get; set; }
    }
}