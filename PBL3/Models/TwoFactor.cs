using System.ComponentModel.DataAnnotations;

namespace PBL3.Models // Hoặc PBL3.Models nếu bạn muốn
{
    public class TwoFactorViewModel // Đổi tên thành TwoFactorViewModel cho rõ ràng hơn
    {
        [Required(ErrorMessage = "Vui lòng nhập mã xác thực.")]
        [StringLength(7, ErrorMessage = "{0} phải có từ {2} đến {1} ký tự.", MinimumLength = 6)] // Mã OTP thường có 6 chữ số
        [Display(Name = "Mã xác thực")]
        public string TwoFactorCode { get; set; }

        [Display(Name = "Ghi nhớ máy tính này?")]
        public bool RememberMachine { get; set; }

        // Thuộc tính này không hiển thị trên form nhưng cần thiết để điều hướng
        // và có thể được truyền ẩn trong form.
        public string? ReturnUrl { get; set; }

        // (Tùy chọn) Nếu bạn muốn cho phép người dùng chọn "Remember me"
        // trong quá trình 2FA, giống như lúc đăng nhập ban đầu.
        // Tuy nhiên, SignInManager.TwoFactorSignInAsync có tham số isPersistent riêng.
        // Bạn có thể không cần thuộc tính này nếu isPersistent luôn là false cho 2FA.
        // [Display(Name = "Ghi nhớ đăng nhập này?")]
        public bool RememberMe { get; set; }
    }
}