// File: ViewModel/EditUserViewModel.cs (hoặc Models/EditUserViewModel.cs)
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel // Hoặc PBL3.Models
{
    public class EditUserViewModel
    {
        public string Id { get; set; }

        [Required(ErrorMessage = "Tên người dùng không được để trống.")]
        [Display(Name = "Tên người dùng/Hiển thị")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email không được để trống.")]
        [EmailAddress(ErrorMessage = "Định dạng email không hợp lệ.")]
        public string Email { get; set; }

        [Display(Name = "Email đã xác nhận")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Bật xác thực hai yếu tố")]
        public bool TwoFactorEnabled { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Mật khẩu mới (để trống nếu không đổi)")]
        // Bạn có thể thêm các validation cho mật khẩu mới nếu muốn
        // [StringLength(100, ErrorMessage = "{0} phải có ít nhất {2} ký tự.", MinimumLength = 6)]
        public string? NewPassword { get; set; }

        // (Tùy chọn) Nếu bạn muốn xác nhận mật khẩu mới
        // [DataType(DataType.Password)]
        // [Display(Name = "Xác nhận mật khẩu mới")]
        // [Compare("NewPassword", ErrorMessage = "Mật khẩu mới và xác nhận mật khẩu không khớp.")]
        // public string ConfirmNewPassword { get; set; }
    }
}