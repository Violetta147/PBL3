using System.ComponentModel.DataAnnotations;
using PBL3.Models;

namespace PBL3.ViewModel
{
    public class ManageAccountViewModel
    {
        public string Id { get; set; } = "";
        
        [Display(Name = "Tên đăng nhập")]
        public string UserName { get; set; } = "";
        
        [Display(Name = "Email")]
        [EmailAddress(ErrorMessage = "Địa chỉ email không hợp lệ.")]
        public string Email { get; set; } = "";
        
        [Display(Name = "Số điện thoại")]
        [Phone(ErrorMessage = "Số điện thoại không hợp lệ.")]
        public string? PhoneNumber { get; set; }
        
        [Display(Name = "Giới tính")]
        public GenderType? Gender { get; set; }
        
        [Display(Name = "Ngày sinh")]
        [DataType(DataType.Date)]
        public DateTime? DateOfBirth { get; set; }
        
        [Display(Name = "Kích hoạt xác thực 2 bước")]
        public bool TwoFactorEnabled { get; set; }
          [Display(Name = "Email đã được xác nhận")]
        public bool IsEmailConfirmed { get; set; }
          [Display(Name = "Số lượng nhà hàng")]
        public int RestaurantCount { get; set; }
        
        public string? StatusMessage { get; set; }
        
        // Property to determine if current user is viewing their own profile
        public bool IsViewingOwnProfile { get; set; }
    }
}
