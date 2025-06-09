using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel.Review
{
    public class UserReviewListItemViewModel
    {
        public int ReviewId { get; set; } // ID của Review

        public int RestaurantId { get; set; } // ID của nhà hàng được review
        [Display(Name = "Nhà hàng")]
        public string RestaurantName { get; set; }
        public string? RestaurantImageUrl { get; set; } // Ảnh đại diện của nhà hàng

        [Display(Name = "Đánh giá")]
        public int Rating { get; set; }

        [Display(Name = "Bình luận")]
        public string? Comment { get; set; }

        [Display(Name = "Ngày đánh giá")]
        [DisplayFormat(DataFormatString = "{0:dd/MM/yyyy HH:mm}")]
        public DateTime ReviewDate { get; set; }

        public List<string> ReviewPhotoUrls { get; set; } // Ảnh của review này

        // URL cho các hành động
        public string ViewRestaurantUrl { get; set; }
        public string EditReviewUrl { get; set; }
        public string DeleteReviewUrl { get; set; } // URL để gọi action xóa (có thể là POST)

        public UserReviewListItemViewModel()
        {
            ReviewPhotoUrls = new List<string>();
        }
    }
}
