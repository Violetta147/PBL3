
// File: Models/CompleteRegistrationViewModel.cs (hoặc ViewModel/)
using System;
using System.ComponentModel.DataAnnotations;
using PBL3.Models; // Cho GenderType

namespace PBL3.ViewModel // Hoặc PBL3.ViewModel
{
    public class CompleteRegistrationViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } // Sẽ được điền sẵn và readonly

        [Required(ErrorMessage = "Vui lòng nhập Tên người dùng.")]
        [Display(Name = "Tên người dùng")]
        public string UserName { get; set; } // Sẽ được điền sẵn hoặc cho phép sửa

        // Mật khẩu không cần hiển thị lại, nhưng cần để validate các trường khác
        // Nếu bạn muốn người dùng nhập lại mật khẩu ở bước này để xác nhận, thì thêm lại.
        // Hiện tại, giả sử mật khẩu đã được xác thực ở modal đăng ký.

        [Display(Name = "Địa chỉ")]
        public string? Address { get; set; }

        [Display(Name = "Giới tính")]
        public GenderType? Gender { get; set; }

        [Display(Name = "Ngày sinh")]
        [DataType(DataType.Date)]
        public DateTime? DateOfBirth { get; set; }

        [Phone(ErrorMessage = "Định dạng số điện thoại không hợp lệ.")]
        [Display(Name = "Số điện thoại")]
        public string? PhoneNumber { get; set; }

        public string? ReturnUrl { get; set; }

        // Các trường ẩn để lưu trữ mật khẩu đã được hash tạm thời hoặc password gốc
        // CẢNH BÁO: Lưu password gốc trong TempData không an toàn.
        // Tốt hơn là hash nó trước khi lưu vào TempData hoặc sử dụng một cơ chế an toàn hơn.
        // Hoặc đơn giản là yêu cầu người dùng nhập lại mật khẩu ở bước này.
        // Để đơn giản, ví dụ này sẽ yêu cầu nhập lại mật khẩu ở bước này.
        [Required(ErrorMessage = "Vui lòng nhập lại mật khẩu để hoàn tất.")]
        [DataType(DataType.Password)]
        [Display(Name = "Nhập lại mật khẩu của bạn")]
        public string PasswordToConfirm { get; set; } // Dùng để hash và tạo user
    }
}