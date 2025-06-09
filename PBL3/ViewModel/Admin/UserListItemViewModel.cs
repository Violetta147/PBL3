using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel.Admin
{
    public class UserListItemViewModel
    {
        public string UserId { get; set; }

        [Display(Name = "Tên đăng nhập")]
        public string? UserName { get; set; }

        [Display(Name = "Email")]
        public string? Email { get; set; }

        [Display(Name = "Tên hiển thị")]
        public string? DisplayName { get; set; }

        [Display(Name = "Vai trò")]
        public IList<string> Roles { get; set; } = new List<string>();

        [Display(Name = "Bị khóa")]
        public bool IsLockedOut { get; set; }

        [Display(Name = "Khóa đến")]
        [DisplayFormat(DataFormatString = "{0:dd/MM/yyyy HH:mm}")]
        public DateTimeOffset? LockoutEnd { get; set; }

        [Display(Name = "Xác thực Email")]
        public bool EmailConfirmed { get; set; }
    }
    public class SelectableRoleViewModel
    {
        public string RoleId { get; set; } // ID của IdentityRole
        public string RoleName { get; set; }
        public bool IsSelected { get; set; } // Người dùng có thuộc vai trò này không
    }

}