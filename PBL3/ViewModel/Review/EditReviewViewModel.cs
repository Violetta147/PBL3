using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using PBL3.ViewModel;

namespace PBL3.ViewModel.Review
{
    // ViewModel con để hiển thị và quản lý ảnh hiện có của Review trong form Edit
    public class ReviewPhotoViewModel // Tương tự RestaurantPhotoViewModel
    {
        public int Id { get; set; } // Id của bản ghi ReviewPhoto
        public string Url { get; set; }
        public string CloudinaryPublicId { get; set; }
        public bool IsMarkedForDeletion { get; set; } = false;
    }

    public class EditReviewViewModel
    {
        [Required]
        public int ReviewId { get; set; }

        [Required]
        public int RestaurantId { get; set; } // Giữ lại để biết review này của nhà hàng nào
        public string? RestaurantName { get; set; } // Để hiển thị

        [Required(ErrorMessage = "Vui lòng chọn số sao đánh giá.")]
        [Range(1, 5, ErrorMessage = "Đánh giá phải từ 1 đến 5 sao.")]
        [Display(Name = "Đánh giá của bạn")]
        public int Rating { get; set; }

        [DataType(DataType.MultilineText)]
        [StringLength(2000, ErrorMessage = "Bình luận không được vượt quá 2000 ký tự.")]
        [Display(Name = "Bình luận của bạn (tùy chọn)")]
        public string? Comment { get; set; }

        // Hiển thị và quản lý các ảnh hiện có của review
        public List<ReviewPhotoViewModel> CurrentPhotos { get; set; }

        [Display(Name = "Tải lên ảnh mới (tùy chọn)")]
        public List<IFormFile>? NewPhotos { get; set; } // Cho phép upload thêm ảnh mới

        public DateTime ReviewDate { get; set; } // Để hiển thị, không cho sửa

        public EditReviewViewModel()
        {
            CurrentPhotos = new List<ReviewPhotoViewModel>();
            NewPhotos = new List<IFormFile>();
        }
    }
}
