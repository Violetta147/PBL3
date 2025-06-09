using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Vui lòng nhập Email.")]
        [EmailAddress(ErrorMessage = "Định dạng Email không hợp lệ.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Vui lòng nhập Mật khẩu.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Ghi nhớ tôi?")]
        public bool Remember { get; set; }

        // Thuộc tính này không hiển thị trên form, dùng để điều hướng sau khi login thành công
        public string? ReturnUrl { get; set; }
    }
}
