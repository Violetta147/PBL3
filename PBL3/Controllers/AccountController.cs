using PBL3.Models;
using PBL3.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using PBL3.Ultilities;

namespace PBL3.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private UserManager<AppUser> _userManager;
        private SignInManager<AppUser> _signInManager;
        public AccountController(UserManager<AppUser> userMgr, SignInManager<AppUser> signinMgr)
        {
            _userManager = userMgr;
            _signInManager = signinMgr;
        }

        [AllowAnonymous]
        public IActionResult Login(string returnUrl)
        {
            Login login = new Login();
            login.ReturnUrl = returnUrl;
            return View(login);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(Login login)
        {
            if (ModelState.IsValid)
            {
                AppUser appUser = await _userManager.FindByEmailAsync(login.Email);
                if (appUser != null)
                {
                    await _signInManager.SignOutAsync(); //!!
                    Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(appUser, login.Password, login.Remember, false);
                    if (result.Succeeded)
                        return Redirect(login.ReturnUrl ?? "/");
                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToAction("LoginTwoStep", new { appUser.Email, login.ReturnUrl });
                    }
                }
                ModelState.AddModelError(nameof(login.Email), "Login Failed: Invalid Email or password");
            }
            return View(login);
        }

        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            string redirectUrl = Url.Action("GoogleResponse", "Account");
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return new ChallengeResult("Google", properties);
        }

        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction(nameof(Login));

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            string[] userInfo = { info.Principal.FindFirst(ClaimTypes.Name).Value, info.Principal.FindFirst(ClaimTypes.Email).Value };
            if (result.Succeeded)
                return View(userInfo);
            else
            {
                AppUser user = new AppUser
                {
                    Email = info.Principal.FindFirst(ClaimTypes.Email).Value,
                    UserName = info.Principal.FindFirst(ClaimTypes.Email).Value
                };

                IdentityResult identResult = await _userManager.CreateAsync(user);
                if (identResult.Succeeded)
                {
                    identResult = await _userManager.AddLoginAsync(user, info);
                    if (identResult.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, false);
                        return View(userInfo);
                    }
                }
                return AccessDenied();
            }
        }
        [AllowAnonymous]
        public async Task<IActionResult> LoginTwoStep(string email, string returnUrl)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found for two-factor authentication.";
                return RedirectToAction(nameof(Login));
            }

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains("Email"))
            {
                TempData["ErrorMessage"] = "Two-factor authentication via Email is not enabled for this user.";
                return RedirectToAction(nameof(Login));
            }

            ViewData["ReturnUrl"] = returnUrl;

            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            EmailHelper emailHelper = new EmailHelper();
            bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

            return View(new TwoFactor());//return LoginTwoStep.cshtml that requires a 2FA ViewModel but it's GET so it's empty 
            //we use the same view for POST so we will pass in a new TwoFactor ViewModel
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginTwoStep(TwoFactor twoFactor, string returnUrl)
        {
            Console.WriteLine("POST Return URL: " + returnUrl); // ~/Home/Secured
            Console.WriteLine("POST TwoFactor Code: " + twoFactor.TwoFactorCode);

            if (!ModelState.IsValid)
            {
                ViewData["ReturnUrl"] = returnUrl;
                return View(twoFactor);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Unable to load user for two-factor authentication.");
                ViewData["ReturnUrl"] = returnUrl;
                return View(twoFactor);
            }

            var authenticatorCode = twoFactor.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
            var result = await _signInManager.TwoFactorSignInAsync("Email", authenticatorCode, isPersistent: false, rememberClient: false);

            if (result.Succeeded)
            {
                return LocalRedirect(returnUrl ?? "/");
            }
            else if (result.IsLockedOut)
            {
                return RedirectToAction("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                ViewData["ReturnUrl"] = returnUrl;
                return View(twoFactor);
            }
        }
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }


        public IActionResult AccessDenied()
        {
            return View();
        }

    }
}