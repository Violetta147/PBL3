// Trong ViewModels/Admin/UserEditRolesViewModel.cs
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel.Admin
{
    public class UserEditRolesViewModel
    {
        [Required]
        public string UserId { get; set; }

        [Display(Name = "Tên đăng nhập")]
        public string? UserName { get; set; } // Chỉ để hiển thị

        [Display(Name = "Tên hiển thị")]
        public string? DisplayName { get; set; } // Chỉ để hiển thị

        // Danh sách tất cả các vai trò có sẵn, với cờ IsSelected
        public List<SelectableRoleViewModel> Roles { get; set; }

        // Thuộc tính này sẽ nhận danh sách tên của các vai trò được chọn từ form khi POST
        // (Tên của các checkbox sẽ là "SelectedRoleNames")
        public List<string> SelectedRoleNames { get; set; }


        public UserEditRolesViewModel()
        {
            Roles = new List<SelectableRoleViewModel>();
            SelectedRoleNames = new List<string>();
        }
    }
}