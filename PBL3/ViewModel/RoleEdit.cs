using Microsoft.AspNetCore.Identity;
using PBL3.Models;
 
namespace PBL3.ViewModel
{
    public class RoleEdit
    {
        public IdentityRole Role { get; set; }
        public IEnumerable<AppUser> Members { get; set; }
        public IEnumerable<AppUser> NonMembers { get; set; }
    }
}