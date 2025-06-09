using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel.Menu
{
    public class MenuEditViewModel
    {
        public int Id { get; set; } // 0 nếu tạo mới

        [Required(ErrorMessage = "Tiêu đề thực đơn không được để trống.")]
        [StringLength(100, MinimumLength = 3, ErrorMessage = "Tiêu đề thực đơn phải từ 3 đến 100 ký tự.")]
        [Display(Name = "Tiêu đề thực đơn")]
        public string Title { get; set; }

        [DataType(DataType.MultilineText)]
        [StringLength(500, ErrorMessage = "Mô tả không được vượt quá 500 ký tự.")]
        [Display(Name = "Mô tả (tùy chọn)")]
        public string? Description { get; set; }

        [Display(Name = "Kích hoạt")]
        public bool IsActive { get; set; } = true;

        [Display(Name = "Thứ tự hiển thị")]
        [Range(0, int.MaxValue, ErrorMessage = "Thứ tự hiển thị phải là số không âm.")]
        public int DisplayOrder { get; set; } = 0;

        // ID của Restaurant mà Menu này thuộc về
        [Required]
        public int RestaurantId { get; set; }
        public string? RestaurantName { get; set; } // Để hiển thị tên Nhà hàng (read-only)
    }
}