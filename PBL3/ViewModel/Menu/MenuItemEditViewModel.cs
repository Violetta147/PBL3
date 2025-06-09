using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.ViewModel.Menu
{
    public class MenuItemEditViewModel
    {
        public int Id { get; set; } // Sẽ là 0 nếu là tạo mới

        [Required(ErrorMessage = "Tên món ăn không được để trống.")]
        [StringLength(150, MinimumLength = 2, ErrorMessage = "Tên món ăn phải từ 2 đến 150 ký tự.")]
        [Display(Name = "Tên món ăn")]
        public string Name { get; set; }

        [DataType(DataType.MultilineText)]
        [StringLength(1000, ErrorMessage = "Mô tả món ăn không được vượt quá 1000 ký tự.")]
        [Display(Name = "Mô tả (tùy chọn)")]
        public string? Description { get; set; }

        [Required(ErrorMessage = "Giá không được để trống.")]
        [Range(0.01, (double)decimal.MaxValue, ErrorMessage = "Giá phải là số dương.")] // Giá thường phải > 0
        [Display(Name = "Giá (VNĐ)")]
        [DataType(DataType.Currency)] // Giúp định dạng
        public decimal Price { get; set; }

        [Display(Name = "Có sẵn")]
        public bool IsAvailable { get; set; } = true;

        [Display(Name = "Món đặc sắc")]
        public bool IsSignatureDish { get; set; } = false;

        [Display(Name = "Thứ tự hiển thị")]
        [Range(0, int.MaxValue, ErrorMessage = "Thứ tự hiển thị phải là số không âm.")]
        public int DisplayOrder { get; set; } = 0;

        // ID của MenuSection mà MenuItem này thuộc về
        [Required(ErrorMessage = "Vui lòng chọn mục trong thực đơn.")]
        public int MenuSectionId { get; set; }
        public string? MenuSectionName { get; set; } // Để hiển thị tên section trên form (read-only)

        // ID của Restaurant chứa MenuItem này (cần cho việc kiểm tra quyền và logic)
        [Required]
        public int RestaurantId { get; set; }
        public string? RestaurantName { get; set; } // Để hiển thị tên nhà hàng (read-only)


        // Ảnh cho MenuItem
        [Display(Name = "Ảnh hiện tại")]
        public string? CurrentMainImageUrl { get; set; } // URL của ảnh hiện tại
        public string? CurrentMainImagePublicId { get; set; } // Cloudinary Public ID của ảnh hiện tại (để xóa)

        [Display(Name = "Tải ảnh mới (nếu muốn thay đổi hoặc thêm mới)")]
        public IFormFile? NewMainImageFile { get; set; }


        // Danh sách Category để người dùng chọn
        [Display(Name = "Phân loại món ăn")]
        public List<SelectableCategoryViewModel> AvailableCategories { get; set; }

        // Danh sách ID của các Category đã được chọn
        public List<int> SelectedCategoryIds { get; set; }


        public MenuItemEditViewModel()
        {
            AvailableCategories = new List<SelectableCategoryViewModel>();
            SelectedCategoryIds = new List<int>();
            IsAvailable = true; // Mặc định
        }
    }

    public class SelectableCategoryViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string? IconUrl { get; set; } // Tùy chọn
        public bool IsSelected { get; set; } // Dùng để đánh dấu checkbox
        public int? ParentCategoryId { get; set; } // Có thể cần nếu muốn hiển thị phân cấp
        public string HierarchyName { get; set; } // Ví dụ: "Đồ Uống > Nước Ngọt"
    }
}
