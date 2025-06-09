// File: ViewModel/CreateUserViewModel.cs (hoặc Models/CreateUserViewModel.cs)
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel // Hoặc PBL3.Models
{
    public class CreateUserViewModel // Hoặc giữ tên là User nếu bạn muốn
    {
        [Required(ErrorMessage = "Vui lòng nhập Tên người dùng/Hiển thị.")]
        [Display(Name = "Tên người dùng/Hiển thị")]
        public string Name { get; set; } // Sẽ được dùng cho AppUser.UserName

        [Required(ErrorMessage = "Vui lòng nhập Email.")]
        [EmailAddress(ErrorMessage = "Định dạng Email không hợp lệ.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Vui lòng nhập Mật khẩu.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}