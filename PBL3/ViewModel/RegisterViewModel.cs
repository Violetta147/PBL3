// File: Models/RegisterViewModel.cs (hoặc PBL3/Models/RegisterViewModel.cs)
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Vui lòng nhập Email.")]
        [EmailAddress(ErrorMessage = "Định dạng Email không hợp lệ.")]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Vui lòng nhập Mật khẩu.")]
        [StringLength(100, ErrorMessage = "{0} phải có ít nhất {2} và tối đa {1} ký tự.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Mật khẩu")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Xác nhận mật khẩu")]
        [Compare("Password", ErrorMessage = "Mật khẩu và mật khẩu xác nhận không khớp.")]
        public string ConfirmPassword { get; set; }

        // Bạn có thể thêm các trường khác nếu cần, ví dụ:
        // [Required(ErrorMessage = "Vui lòng nhập Tên người dùng.")]
        // [Display(Name = "Tên người dùng")]
        // public string UserName { get; set; }

        // [Display(Name = "Họ và Tên")]
        // public string FullName { get; set; }

        public string? ReturnUrl { get; set; }
    }
}