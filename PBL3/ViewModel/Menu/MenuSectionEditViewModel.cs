using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel.Menu
{
    public class MenuSectionEditViewModel
    {
        public int Id { get; set; } // 0 nếu tạo mới

        [Required(ErrorMessage = "Tiêu đề mục không được để trống.")]
        [StringLength(100, MinimumLength = 2, ErrorMessage = "Tiêu đề mục phải từ 2 đến 100 ký tự.")]
        [Display(Name = "Tiêu đề mục")]
        public string Title { get; set; }

        [DataType(DataType.MultilineText)]
        [StringLength(500, ErrorMessage = "Mô tả không được vượt quá 500 ký tự.")]
        [Display(Name = "Mô tả (tùy chọn)")]
        public string? Description { get; set; }

        [Display(Name = "Thứ tự hiển thị")]
        [Range(0, int.MaxValue, ErrorMessage = "Thứ tự hiển thị phải là số không âm.")]
        public int DisplayOrder { get; set; } = 0;

        // ID của Menu mà MenuSection này thuộc về
        [Required]
        public int MenuId { get; set; }
        public string? MenuName { get; set; } // Để hiển thị tên Menu (read-only)

        // ID của Restaurant (để kiểm tra quyền)
        [Required]
        public int RestaurantId { get; set; }
    }
}