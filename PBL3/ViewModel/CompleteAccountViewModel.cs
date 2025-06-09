// File: Models/CompleteAccountViewModel.cs (hoặc ViewModel/CompleteAccountViewModel.cs)
using System; // Cho DateTime
using System.ComponentModel.DataAnnotations;
using PBL3.Models; // Bỏ comment nếu GenderType nằm trong namespace này và ViewModel ở namespace khác

namespace PBL3.ViewModel // Hoặc PBL3.ViewModel
{
    public class CompleteAccountViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email (từ nhà cung cấp)")]
        public string Email { get; set; }

        [Display(Name = "Tên hiển thị (gợi ý)")]
        public string? SuggestedDisplayName { get; set; }

        [Required(ErrorMessage = "Vui lòng nhập Tên người dùng mong muốn.")]
        [Display(Name = "Tên người dùng (cho FishLoot)")]
        public string UserName { get; set; }

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
        public string? Address { get; set; } // THAY ĐỔI TỪ ZipCode

        [Display(Name = "Giới tính")]
        public GenderType? Gender { get; set; } // THÊM MỚI

        [Display(Name = "Ngày sinh")]
        [DataType(DataType.Date)] // Giúp trình duyệt hiển thị date picker (nếu hỗ trợ)
        public DateTime? DateOfBirth { get; set; } // THÊM MỚI

        [Phone(ErrorMessage = "Định dạng số điện thoại không hợp lệ.")]
        [Display(Name = "Số điện thoại")]
        public string? PhoneNumber { get; set; }

        public string? ReturnUrl { get; set; }
        [Required]
        public string LoginProvider { get; set; }
        [Required]
        public string ProviderKey { get; set; }
        public string? ProviderDisplayName { get; set; }
    }
}