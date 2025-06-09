// Trong thư mục ViewModels/Review/ (hoặc ViewModels/)
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel.Review
{
    public class CreateReviewViewModel
    {
        [Required]
        public int RestaurantId { get; set; }
        public string? RestaurantName { get; set; }

        [Required(ErrorMessage = "Vui lòng chọn số sao đánh giá.")]
        [Range(1, 5, ErrorMessage = "Đánh giá phải từ 1 đến 5 sao.")]
        [Display(Name = "Đánh giá của bạn")]
        public int Rating { get; set; }

        [DataType(DataType.MultilineText)]
        [StringLength(2000, ErrorMessage = "Bình luận không được vượt quá 2000 ký tự.")]
        [Display(Name = "Bình luận của bạn (tùy chọn)")]
        public string? Comment { get; set; }

        [Display(Name = "Hình ảnh đính kèm (tùy chọn)")]
        public List<IFormFile>? Photos { get; set; }

        public CreateReviewViewModel()
        {
            Photos = new List<IFormFile>();
        }
    }
}