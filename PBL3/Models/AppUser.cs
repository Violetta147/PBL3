using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace PBL3.Models
{
    public enum GenderType // Enum để định nghĩa các lựa chọn giới tính
    {
        [Display(Name = "Nam")]
        Male,
        [Display(Name = "Nữ")]
        Female,
        [Display(Name = "Khác")]
        Other
    }

    public class AppUser : IdentityUser
    {
        public string? DisplayName { get; set; } // Tên hiển thị (có thể khác UserName)
        public virtual ICollection<Address> Addresses { get; set; } // Sổ địa chỉ của người dùng
        public GenderType? Gender { get; set; } // Sử dụng enum cho giới tính
        public DateTime? DateOfBirth { get; set; } // Ngày sinh, cho phép null

        // public bool IsProfileCompleted { get; set; } // Cờ bạn có thể dùng
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; } // UpdatedAt có thể là nullable ban đầu

        [StringLength(500)] // Độ dài URL có thể thay đổi
        [Url(ErrorMessage = "Đường dẫn ảnh đại diện không hợp lệ.")] // Optional: để validate nếu giá trị được nhập
        public string? AvatarUrl { get; set; }

        [StringLength(200)] // Lưu Public ID của avatar hiện tại trên Cloudinary
        public string? AvatarCloudinaryPublicId { get; set; }
        public virtual ICollection<UserPromotionUsage> PromotionUsages { get; set; }
        public AppUser()
        {
            Addresses = new HashSet<Address>();
            PromotionUsages = new HashSet<UserPromotionUsage>();
            CreatedAt = DateTime.UtcNow;
        }
    }
}