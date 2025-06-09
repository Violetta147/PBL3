using System; // Cho DateTime
using System.ComponentModel.DataAnnotations;
using PBL3.Models; // THÊM DÒNG NÀY nếu GenderType enum được định nghĩa trong namespace PBL3.Models

namespace PBL3.ViewModel // Hoặc namespace PBL3.Models nếu bạn đặt ViewModel ở đó
{
    public class FinalizeExternalRegistrationViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email (từ nhà cung cấp)")]
        public string Email { get; set; } // Sẽ được điền sẵn và có thể là readonly

        [Display(Name = "Tên hiển thị (gợi ý)")]
        public string? SuggestedDisplayName { get; set; } // Gợi ý từ nhà cung cấp

        [Required(ErrorMessage = "Vui lòng nhập Tên người dùng mong muốn.")]
        [Display(Name = "Tên người dùng (cho FishLoot)")]
        // Bạn có thể thêm các validation khác cho UserName ở đây nếu cần (ví dụ: RegularExpression)
        public string UserName { get; set; } // Người dùng sẽ nhập hoặc chỉnh sửa

        [Required(ErrorMessage = "Vui lòng nhập mật khẩu.")]
        [StringLength(100, ErrorMessage = "{0} phải có ít nhất {2} và tối đa {1} ký tự.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Mật khẩu")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Xác nhận mật khẩu")]
        [Compare("Password", ErrorMessage = "Mật khẩu và mật khẩu xác nhận không khớp.")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "Địa chỉ")]
        public string? Address { get; set; } // ĐÃ THAY THẾ ZipCode

        [Display(Name = "Giới tính")]
        public GenderType? Gender { get; set; } // ĐÃ THÊM - Kiểu là GenderType từ PBL3.Models

        [Display(Name = "Ngày sinh")]
        [DataType(DataType.Date)] // Giúp trình duyệt hiển thị date picker
        public DateTime? DateOfBirth { get; set; } // ĐÃ THÊM

        [Phone(ErrorMessage = "Định dạng số điện thoại không hợp lệ.")]
        [Display(Name = "Số điện thoại")]
        public string? PhoneNumber { get; set; }

        public string? ReturnUrl { get; set; }

        // Các trường ẩn để lưu trữ thông tin từ ExternalLoginInfo
        [Required]
        public string LoginProvider { get; set; }
        [Required]
        public string ProviderKey { get; set; }
        public string? ProviderDisplayName { get; set; }
    }
}