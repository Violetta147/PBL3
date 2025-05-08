using PBL3.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
 
namespace PBL3.Controllers
{
    public class EmailController : Controller
    {
        private UserManager<AppUser> _userManager;
        public EmailController(UserManager<AppUser> usrMgr)
        {
            _userManager = usrMgr;
        }
 
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return View("Error");
 
            var result = await _userManager.ConfirmEmailAsync(user, token);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }
    }
}