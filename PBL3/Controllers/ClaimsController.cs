using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PBL3.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace PBL3.Controllers
{
    [Authorize]
    public class ClaimsController : Controller
    {   
        private UserManager<AppUser> _userManager;
        private IAuthorizationService _authService;

        public ClaimsController(UserManager<AppUser> userMgr, IAuthorizationService authService)
        {
            _userManager = userMgr;
            _authService = authService;
        }
        public ViewResult Index() => View(User?.Claims);

        public ViewResult Create() => View();

        [HttpPost]
        [ActionName("Create")]
        public async Task<IActionResult> Create_Post(string claimType, string claimValue)
        {
            AppUser user = await _userManager.GetUserAsync(HttpContext.User);
            Claim claim = new Claim(claimType, claimValue, ClaimValueTypes.String);
            IdentityResult result = await _userManager.AddClaimAsync(user, claim);
 
            if (result.Succeeded)
                return RedirectToAction("Index");
            else
                Errors(result);
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Delete(string claimValues)
        {
            AppUser user = await _userManager.GetUserAsync(HttpContext.User);
 
            string[] claimValuesArray = claimValues.Split(";");
            string claimType = claimValuesArray[0], claimValue = claimValuesArray[1], claimIssuer = claimValuesArray[2];
 
            Claim claim = User.Claims.Where(x => x.Type == claimType && x.Value == claimValue && x.Issuer == claimIssuer).FirstOrDefault();
 
            IdentityResult result = await _userManager.RemoveClaimAsync(user, claim);
 
            if (result.Succeeded)
                return RedirectToAction("Index");
            else
                Errors(result);
 
            return View("Index");
        }
 
        void Errors(IdentityResult result)
        {
            foreach (IdentityError error in result.Errors)
                ModelState.AddModelError("", error.Description);
        }
        [Authorize(Policy = "AspManager")]
        public IActionResult Project() => View("Index", User?.Claims);

        [Authorize(Policy = "AllowTom")]
        public IActionResult TomFiles() => View("Index", User?.Claims);
        public async Task<IActionResult> PrivateAccess(string title)
        {
            string[] allowedUsers = { "tom", "alice" };
            AuthorizationResult authorized = await _authService.AuthorizeAsync(User, allowedUsers, "PrivateAccess");
 
            if (authorized.Succeeded)
                return View("Index", User?.Claims);
            else
                return new ChallengeResult();
        }
    }

}