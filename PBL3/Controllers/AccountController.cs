using PBL3.Models;
using PBL3.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using PBL3.Ultilities; // Đảm bảo using này
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Threading.Tasks; // Cho Task
using Microsoft.Extensions.Logging;
using System.Globalization;
using PBL3.Data;
using Microsoft.EntityFrameworkCore;
using PBL3.Services.Interfaces;
// using Microsoft.AspNetCore.Identity.UI.Services;

namespace PBL3.Controllers
{    [Authorize]    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly ILogger<AdminController> _logger;
        private readonly IEmailSender _emailSender;
        private readonly EmailHelper _emailHelper; // Thêm DI cho EmailHelper
        private readonly IRestaurantService _restaurantService;
        private readonly ApplicationDbContext _context; // Kept only for GetRestaurantReviews method - should be refactored to use a ReviewService

        public AccountController(
            UserManager<AppUser> userMgr,
            SignInManager<AppUser> signinMgr,
            IEmailSender emailSender,
            EmailHelper emailHelper,
            IRestaurantService restaurantService,
            ApplicationDbContext context, // Kept only for GetRestaurantReviews - should be replaced with ReviewService
            ILogger<AdminController> logger = null) // Inject RestaurantService
        {
            _userManager = userMgr;
            _signInManager = signinMgr;
            _emailSender = emailSender; // Gán giá trị cho _emailSender
            _emailHelper = emailHelper; // Gán giá trị
            _restaurantService = restaurantService;
            _context = context; // Temporary - should be removed when ReviewService is implemented
            _logger = logger;
        }

        // ACTION ĐỂ TẢI NỘI DUNG CHO MODAL ĐĂNG NHẬP
        [AllowAnonymous]
        [HttpGet]
        public IActionResult LoginModal(string? returnUrl = null)
        {
            var model = new LoginViewModel
            {
                ReturnUrl = returnUrl
            };
            return PartialView("_LoginModalPartial", model);
        }

        // Action Login(GET) đã bị xóa vì không cần trang đăng nhập riêng

        // POST: /Account/Login (Xử lý submit từ modal)
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel)
        {
            loginViewModel.ReturnUrl ??= Url.Content("~/");

            if (ModelState.IsValid)
            {
                AppUser appUser = await _userManager.FindByEmailAsync(loginViewModel.Email);
                if (appUser != null)
                {
                    await _signInManager.SignOutAsync();
                    var result = await _signInManager.PasswordSignInAsync(appUser, loginViewModel.Password, loginViewModel.Remember, lockoutOnFailure: true);

                    if (result.Succeeded)
                    {
                        _logger.LogInformation("User logged in via modal.");
                        var user = await _userManager.FindByEmailAsync(loginViewModel.Email); // Hoặc Input.Email nếu là Razor Page
                        if (user != null && await _userManager.IsInRoleAsync(user, "Admin"))
                        {
                            return Json(new { success = true, redirectUrl = Url.Action("Index", "AdminDashboard") }); // Không cần Area nếu không dùng Area
                        }
                        // Nếu là user thường
                        if (!string.IsNullOrEmpty(loginViewModel.ReturnUrl) && Url.IsLocalUrl(loginViewModel.ReturnUrl))
                        {
                            return Json(new { success = true, redirectUrl = loginViewModel.ReturnUrl });
                        }
                        return Json(new { success = true, redirectUrl = Url.Action("Index", "Home") });
                    }
                    if (result.RequiresTwoFactor)
                    {
                        // Chuyển hướng đến LoginTwoStep để gửi mã 2FA và xử lý
                        if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                        {
                            return Json(new { success = true, redirectUrl = Url.Action("LoginTwoStep", new { email = loginViewModel.Email, returnUrl = loginViewModel.ReturnUrl }) });
                        }
                        return RedirectToAction("LoginTwoStep", new { email = loginViewModel.Email, returnUrl = loginViewModel.ReturnUrl });
                    }
                    else if (result.IsLockedOut)
                    {
                        ModelState.AddModelError(string.Empty, "Tài khoản của bạn đã bị khóa. Vui lòng đợi và thử lại.");
                    }
                    else
                    {
                        bool emailStatus = await _userManager.IsEmailConfirmedAsync(appUser);
                        if (!emailStatus)
                        {
                            ModelState.AddModelError(nameof(loginViewModel.Email), "Email chưa được xác nhận. Vui lòng xác nhận email trước.");
                        }
                        else
                        {
                            ModelState.AddModelError(string.Empty, "Đăng nhập không thành công: Email hoặc mật khẩu không hợp lệ.");
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Đăng nhập không thành công: Email hoặc mật khẩu không hợp lệ.");
                }
            }

            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                return PartialView("_LoginModalPartial", loginViewModel);
            }

            // Nếu không phải AJAX và có lỗi:
            // Dòng này sẽ tìm View("Login", loginViewModel). Vì Login.cshtml đã xóa, cần xử lý khác.
            // Tạm thời, chúng ta có thể redirect về trang chủ và người dùng sẽ phải mở lại modal.
            // Hoặc, nếu bạn muốn giữ lại một trang lỗi cơ bản, bạn có thể tạo một view riêng.
            TempData["LoginError"] = "Thông tin đăng nhập không chính xác hoặc có lỗi xảy ra."; // Ví dụ thông báo lỗi
            return RedirectToAction("Index", "Home"); // Chuyển hướng về trang chủ
        }

        // ACTION ĐỂ TẢI NỘI DUNG CHO MODAL ĐĂNG KÝ
        [AllowAnonymous]
        [HttpGet]
        public IActionResult RegisterModal(string? returnUrl = null)
        {
            var model = new RegisterViewModel { ReturnUrl = returnUrl };
            return PartialView("_RegisterModalPartial", model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model) // Model từ modal đăng ký
        {
            model.ReturnUrl ??= Url.Content("~/");

            // Chỉ validate các trường cơ bản của RegisterViewModel (Email, Password, ConfirmPassword)
            // Không kiểm tra UserName ở đây nếu nó sẽ được nhập/xác nhận ở bước sau.
            if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password) || model.Password != model.ConfirmPassword)
            {
                // Nếu có lỗi cơ bản, trả về modal với lỗi
                if (!string.IsNullOrEmpty(model.Email) && !string.IsNullOrEmpty(model.Password) && model.Password != model.ConfirmPassword)
                {
                    ModelState.AddModelError("ConfirmPassword", "Mật khẩu và xác nhận mật khẩu không khớp.");
                }
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return PartialView("_RegisterModalPartial", model);
                }
                return View("Register", model); // Hoặc redirect nếu không còn trang Register riêng
            }

            // Kiểm tra xem email đã tồn tại chưa TRƯỚC KHI chuyển hướng
            var existingUserByEmail = await _userManager.FindByEmailAsync(model.Email);
            if (existingUserByEmail != null)
            {
                ModelState.AddModelError("Email", "Địa chỉ email này đã được sử dụng. Vui lòng sử dụng email khác hoặc đăng nhập.");
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return PartialView("_RegisterModalPartial", model);
                }
                return View("Register", model);
            }

            // Lưu thông tin vào TempData để chuyển sang bước hoàn tất
            TempData["PendingRegistrationEmail"] = model.Email;
            TempData["PendingRegistrationPassword"] = model.Password; // LƯU Ý BẢO MẬT - Sẽ yêu cầu nhập lại ở bước sau
            TempData["PendingRegistrationReturnUrl"] = model.ReturnUrl;
            // Nếu RegisterViewModel có UserName, bạn cũng có thể lưu nó:
            // TempData["PendingRegistrationUserName"] = model.UserName;


            _logger?.LogInformation("User {Email} initiated registration, redirecting to complete profile.", model.Email);

            // Chuyển hướng đến action hoàn tất đăng ký
            // Truyền email và username (nếu có) qua route để điền sẵn vào form
            return Json(new { success = true, redirectUrl = Url.Action("CompleteRegistration", new { email = model.Email, returnUrl = model.ReturnUrl /*, userName = model.UserName */ }) });
        }


        [AllowAnonymous]
        [HttpGet]
        public IActionResult RegisterConfirmation(string? email, string? returnUrl)
        {
            if (string.IsNullOrEmpty(email))
            {
                // Xử lý trường hợp email không được cung cấp
                return RedirectToAction("Index", "Home");
            }
            ViewData["Email"] = email;
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string? userId, string? code, string? returnUrl)
        {
            if (userId == null || code == null)
            {
                return RedirectToAction("Index", "Home");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Không thể tải người dùng với ID '{userId}'.");
            }
            try
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            }
            catch (FormatException)
            {
                ViewData["StatusMessage"] = "Lỗi: Mã xác nhận không hợp lệ.";
                return View();
            }

            var result = await _userManager.ConfirmEmailAsync(user, code);
            ViewData["StatusMessage"] = result.Succeeded ? "Cảm ơn bạn đã xác nhận email." : "Lỗi xác nhận email.";
            if (result.Succeeded)
            {
                // Tùy chọn: Đăng nhập người dùng sau khi xác nhận thành công
                // await _signInManager.SignInAsync(user, isPersistent: false);
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    ViewData["SuccessReturnUrl"] = returnUrl; // Để hiển thị link "Tiếp tục" trên view
                }
            }
            return View();
        }

        // --- GOOGLE LOGIN ---
        //[AllowAnonymous]
        //public IActionResult GoogleLogin()
        //{
        //    string redirectUrl = Url.Action(nameof(GoogleResponse), "Account"); // Nên dùng nameof
        //    var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
        //    return new ChallengeResult("Google", properties);
        //}

        //[AllowAnonymous]
        //public async Task<IActionResult> GoogleResponse(string? returnUrl = null, string? remoteError = null)
        //{
        //    returnUrl ??= Url.Content("~/");
        //    if (remoteError != null)
        //    {
        //        ModelState.AddModelError(string.Empty, $"Lỗi từ nhà cung cấp bên ngoài: {remoteError}");
        //        return RedirectToAction("Index", "Home"); // Hoặc trang hiển thị lỗi
        //    }
        //    ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();
        //    if (info == null)
        //    {
        //        ModelState.AddModelError(string.Empty, "Lỗi tải thông tin đăng nhập bên ngoài.");
        //        return RedirectToAction("Index", "Home"); // Hoặc trang hiển thị lỗi
        //    }

        //    var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
        //    if (signInResult.Succeeded)
        //    {
        //        return LocalRedirect(returnUrl);
        //    }
        //    if (signInResult.IsLockedOut)
        //    {
        //        return RedirectToAction(nameof(Lockout)); // Cần tạo action Lockout
        //    }
        //    else // Nếu người dùng chưa có tài khoản local
        //    {
        //        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        //        if (email != null)
        //        {
        //            var user = await _userManager.FindByEmailAsync(email);
        //            if (user == null) // Tạo user mới nếu chưa có
        //            {
        //                user = new AppUser { UserName = email, Email = email, EmailConfirmed = true }; // Mặc định EmailConfirmed = true cho login bên ngoài
        //                var createUserResult = await _userManager.CreateAsync(user);
        //                if (!createUserResult.Succeeded)
        //                {
        //                    foreach (var error in createUserResult.Errors) ModelState.AddModelError(string.Empty, error.Description);
        //                    return View("ExternalLoginFailure"); // Cần View này
        //                }
        //            }
        //            // Liên kết tài khoản bên ngoài với tài khoản local
        //            var addLoginResult = await _userManager.AddLoginAsync(user, info);
        //            if (addLoginResult.Succeeded)
        //            {
        //                await _signInManager.SignInAsync(user, isPersistent: false);
        //                return LocalRedirect(returnUrl);
        //            }
        //            foreach (var error in addLoginResult.Errors) ModelState.AddModelError(string.Empty, error.Description);
        //            return View("ExternalLoginFailure"); // Cần View này
        //        }
        //        ModelState.AddModelError(string.Empty, "Không thể lấy thông tin email từ Google.");
        //        return View("ExternalLoginFailure"); // Cần View này
        //    }
        //}

        [AllowAnonymous]
        public IActionResult Lockout() // Action mới cho tài khoản bị khóa
        {
            return View(); // Cần View Views/Account/Lockout.cshtml
        }


        // --- TWO FACTOR AUTHENTICATION ---
        [AllowAnonymous]
        public async Task<IActionResult> LoginTwoStep(string email, string? returnUrl = null)
        {
            if (string.IsNullOrEmpty(email)) return RedirectToAction("Index", "Home");
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy người dùng để xác thực hai yếu tố.";
                return RedirectToAction("Index", "Home");
            }

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains("Email"))
            {
                TempData["ErrorMessage"] = "Xác thực hai yếu tố qua Email chưa được kích hoạt cho người dùng này.";
                return RedirectToAction("Index", "Home");
            }

            returnUrl ??= Url.Content("~/");
            ViewData["ReturnUrl"] = returnUrl;            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            bool emailSent = await _emailHelper.SendEmailTwoFactorCodeAsync(user.Email ?? "", token);
            if (!emailSent) TempData["ErrorMessage"] = "Lỗi khi gửi mã xác thực.";

            return View(new TwoFactorViewModel { ReturnUrl = returnUrl ?? Url.Content("~/") });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginTwoStep(TwoFactorViewModel twoFactor)
        {
            twoFactor.ReturnUrl ??= Url.Content("~/");
            if (!ModelState.IsValid) return View(twoFactor);

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Không thể tải người dùng để xác thực hai yếu tố.");
                return View(twoFactor);
            }

            var authenticatorCode = twoFactor.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
            var result = await _signInManager.TwoFactorSignInAsync("Email", authenticatorCode, twoFactor.RememberMe, twoFactor.RememberMachine);

            if (result.Succeeded) return LocalRedirect(twoFactor.ReturnUrl);
            if (result.IsLockedOut) return RedirectToAction(nameof(Lockout));

            ModelState.AddModelError(string.Empty, "Mã xác thực không hợp lệ.");
            return View(twoFactor);
        }

        // --- LOGOUT ---
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        // --- FORGOT PASSWORD & RESET PASSWORD ---
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword([Required(ErrorMessage = "Vui lòng nhập email.")] string email)
        {
            if (!ModelState.IsValid) return View((object)email);

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token)); // Mã hóa token
            var link = Url.Action(nameof(ResetPassword), "Account", new { token, email = user.Email }, Request.Scheme);            bool emailSent = await _emailHelper.SendEmailPasswordResetAsync(user.Email ?? "",
                $"Vui lòng đặt lại mật khẩu của bạn bằng cách <a href='{HtmlEncoder.Default.Encode(link ?? "")}'>nhấn vào đây</a>.");

            if (emailSent) return RedirectToAction(nameof(ForgotPasswordConfirmation));

            ModelState.AddModelError(string.Empty, "Lỗi khi gửi email đặt lại mật khẩu.");
            return View((object)email);
        }

        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpGet]
        public IActionResult ResetPassword(string? token = null, string? email = null)
        {
            if (token == null || email == null)
            {
                ModelState.AddModelError(string.Empty, "Token hoặc email đặt lại mật khẩu không hợp lệ.");
            }
            return View(new ResetPassword { Token = token, Email = email });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            if (!ModelState.IsValid) return View(resetPassword);

            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user == null) return RedirectToAction(nameof(ResetPasswordConfirmation));

            string decodedToken;
            try
            {
                decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetPassword.Token));
            }
            catch (FormatException)
            {
                ModelState.AddModelError(string.Empty, "Token đặt lại mật khẩu không hợp lệ.");
                return View(resetPassword);
            }

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, resetPassword.Password);
            if (result.Succeeded) return RedirectToAction(nameof(ResetPasswordConfirmation));

            foreach (var error in result.Errors) ModelState.AddModelError(string.Empty, error.Description);
            return View(resetPassword);
        }

        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        // --- ACCESS DENIED ---
        [AllowAnonymous] // Cho phép truy cập trang AccessDenied mà không cần đăng nhập (nếu bị từ chối từ policy)
        public IActionResult AccessDenied()
        {
            return View();
        }

        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken] // Quan trọng cho POST request
        public IActionResult ExternalLogin(string provider, string? returnUrl = null)
        {
            // Yêu cầu chuyển hướng đến nhà cung cấp bên ngoài.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
        {
            returnUrl ??= Url.Content("~/");
            if (remoteError != null)
            {
                TempData["ErrorMessage"] = $"Lỗi từ nhà cung cấp bên ngoài: {remoteError}";
                _logger?.LogWarning("External login provider error: {RemoteError}", remoteError);
                return RedirectToAction(nameof(LoginModal), new { returnUrl }); // Quay lại modal login nếu có lỗi từ provider
            }

            ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                TempData["ErrorMessage"] = "Không thể lấy thông tin đăng nhập từ nhà cung cấp bên ngoài. Vui lòng thử lại.";
                _logger?.LogError("ExternalLoginInfo is null after attempting external login.");
                return RedirectToAction(nameof(LoginModal), new { returnUrl });
            }

            // Thử đăng nhập ngay. Nếu thành công, nghĩa là user đã tồn tại và đã liên kết.
            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (signInResult.Succeeded)
            {
                _logger?.LogInformation("User {UserName} logged in with {LoginProvider} provider.", info.Principal.Identity.Name, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
            if (signInResult.IsLockedOut)
            {
                _logger?.LogWarning("User account is locked out for external login with provider {LoginProvider}.", info.LoginProvider);
                return RedirectToAction(nameof(Lockout));
            }
            // Nếu ExternalLoginSignInAsync thất bại (và không phải lockout), nghĩa là đây là lần đầu user này
            // dùng external login này, hoặc tài khoản local chưa được liên kết.
            // Chúng ta sẽ chuyển họ đến trang hoàn tất đăng ký.

            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
            {
                TempData["ErrorMessage"] = "Không thể lấy địa chỉ email từ tài khoản " + info.LoginProvider + ". Vui lòng đảm bảo bạn đã cấp quyền truy cập email.";
                return RedirectToAction(nameof(LoginModal), new { returnUrl });
            }

            // Kiểm tra xem email này đã được sử dụng cho một tài khoản cục bộ nào chưa
            var existingUserByEmail = await _userManager.FindByEmailAsync(email);
            if (existingUserByEmail != null)
            {
                // Email này đã tồn tại. Kiểm tra xem nó đã liên kết với external login này chưa.
                // (ExternalLoginSignInAsync ở trên đã thất bại, nên có thể chưa liên kết hoặc có vấn đề)
                // Trường hợp phức tạp: Email đã tồn tại, nhưng external login này chưa được liên kết với user đó,
                // HOẶC external login này đã được liên kết với MỘT USER KHÁC (có email khác user này).
                // Để đơn giản hóa ban đầu, chúng ta sẽ báo lỗi nếu email đã tồn tại và chưa thể tự động liên kết.
                _logger?.LogWarning("External login attempt for email {Email} which already exists locally (UserId: {UserId}) but ExternalLoginSignInAsync failed.", email, existingUserByEmail.Id);
                TempData["ErrorMessage"] = $"Địa chỉ email '{email}' đã được sử dụng cho một tài khoản khác trên FishLoot. " +
                                           $"Nếu đó là tài khoản của bạn, vui lòng đăng nhập bằng email và mật khẩu, sau đó bạn có thể liên kết tài khoản {info.LoginProvider} trong phần cài đặt tài khoản. " +
                                           $"Hoặc, sử dụng một tài khoản {info.LoginProvider} khác.";
                return RedirectToAction(nameof(LoginModal), new { returnUrl });
            }

            // Nếu email chưa tồn tại, chuẩn bị dữ liệu cho trang hoàn tất đăng ký
            var model = new FinalizeExternalRegistrationViewModel
            {
                Email = email,
                SuggestedDisplayName = info.Principal.FindFirstValue(ClaimTypes.Name),
                UserName = email.Split('@')[0], // Gợi ý UserName ban đầu
                ReturnUrl = returnUrl,
                LoginProvider = info.LoginProvider,
                ProviderKey = info.ProviderKey,
                ProviderDisplayName = info.ProviderDisplayName
            };

            // Lưu trữ thông tin cần thiết để sử dụng ở bước POST (ProviderKey là quan trọng nhất)
            // TempData chỉ tồn tại qua một redirect.
            TempData["ExternalLoginProvider"] = info.LoginProvider;
            TempData["ExternalProviderKey"] = info.ProviderKey;
            TempData["ExternalProviderDisplayName"] = info.ProviderDisplayName;
            // Bạn cũng có thể muốn lưu các claim khác nếu cần, nhưng hãy cẩn thận với kích thước TempData

            return RedirectToAction(nameof(FinalizeExternalRegistration), new { returnUrl = returnUrl, email = email, suggestedName = model.SuggestedDisplayName });
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> CompleteAccount(string? returnUrl = null)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
            var suggestedNameFromProvider = externalLoginInfo?.Principal.FindFirstValue(ClaimTypes.Name);

            var model = new CompleteAccountViewModel
            {
                Email = user.Email,
                SuggestedDisplayName = suggestedNameFromProvider ?? user.UserName, // Lấy tên từ provider làm gợi ý
                UserName = user.UserName, // Hoặc một logic khác để gợi ý UserName
                ReturnUrl = returnUrl,
                //Address = user.Address,     // Đọc từ user
                Gender = user.Gender,       // Đọc từ user
                DateOfBirth = user.DateOfBirth, // Đọc từ user
                PhoneNumber = user.PhoneNumber, // Đọc từ user
                LoginProvider = externalLoginInfo?.LoginProvider, // Cần để POST lại nếu có lỗi
                ProviderKey = externalLoginInfo?.ProviderKey,
                ProviderDisplayName = externalLoginInfo?.ProviderDisplayName
            };
            return View(model);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CompleteAccount(CompleteAccountViewModel model)
        {
            if (!ModelState.IsValid)
            {
                // Nếu model không hợp lệ, cần gán lại các giá trị không submit qua form nếu cần
                // Ví dụ: SuggestedDisplayName nếu nó không phải là input field
                // var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
                // model.SuggestedDisplayName = externalLoginInfo?.Principal.FindFirstValue(ClaimTypes.Name) ?? model.Email.Split('@')[0];
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
            {
                var addPasswordResult = await _userManager.AddPasswordAsync(user, model.Password);
                if (!addPasswordResult.Succeeded)
                {
                    AddErrors(addPasswordResult);
                    return View(model);
                }
                _logger?.LogInformation("User {UserId} set their password.", user.Id);
            }

            bool infoUpdated = false;

            // Cập nhật UserName nếu có thay đổi và hợp lệ
            if (user.UserName != model.UserName && !string.IsNullOrEmpty(model.UserName))
            {
                var setUserNameResult = await _userManager.SetUserNameAsync(user, model.UserName);
                if (!setUserNameResult.Succeeded)
                {
                    AddErrors(setUserNameResult);
                    return View(model);
                }
                infoUpdated = true;
            }


            //if (user.Address != model.Address)
            //{
            //    user.Address = model.Address;
            //    infoUpdated = true;
            //}
            if (user.Gender != model.Gender)
            {
                user.Gender = model.Gender;
                infoUpdated = true;
            }
            if (user.DateOfBirth != model.DateOfBirth)
            {
                user.DateOfBirth = model.DateOfBirth;
                infoUpdated = true;
            }
            if (user.PhoneNumber != model.PhoneNumber)
            {
                user.PhoneNumber = model.PhoneNumber;
                infoUpdated = true;
            }

            if (infoUpdated)
            {
                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    AddErrors(updateResult);
                    return View(model);
                }
                _logger?.LogInformation("User {UserId} updated their profile information.", user.Id);
            }

            await _signInManager.RefreshSignInAsync(user);
            TempData["StatusMessage"] = "Tài khoản của bạn đã được cập nhật thành công.";

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return LocalRedirect(model.ReturnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult FinalizeExternalRegistration(string returnUrl, string email, string? suggestedName)
        {
            // Lấy thông tin provider đã lưu từ TempData
            var loginProvider = TempData["ExternalLoginProvider"]?.ToString();
            var providerKey = TempData["ExternalProviderKey"]?.ToString(); // Quan trọng để AddLoginAsync
            var providerDisplayName = TempData["ExternalProviderDisplayName"]?.ToString();

            // Giữ lại TempData để nếu POST thất bại và trả về View, nó vẫn còn cho lần submit sau
            TempData.Keep("ExternalLoginProvider");
            TempData.Keep("ExternalProviderKey");
            TempData.Keep("ExternalProviderDisplayName");


            if (string.IsNullOrEmpty(loginProvider) || string.IsNullOrEmpty(providerKey))
            {
                // Nếu không có thông tin provider, không thể tiếp tục
                TempData["ErrorMessage"] = "Phiên hoàn tất đăng ký đã hết hạn hoặc không hợp lệ. Vui lòng thử đăng nhập lại.";
                return RedirectToAction(nameof(LoginModal), new { returnUrl });
            }

            var model = new FinalizeExternalRegistrationViewModel
            {
                Email = email,
                SuggestedDisplayName = suggestedName,
                UserName = email.Split('@')[0], // Gợi ý lại UserName
                ReturnUrl = returnUrl,
                LoginProvider = loginProvider,
                ProviderKey = providerKey, // Truyền ProviderKey vào model để form POST có thể gửi lại
                ProviderDisplayName = providerDisplayName
            };
            return View(model); // Trả về Views/Account/FinalizeExternalRegistration.cshtml
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> FinalizeExternalRegistration(FinalizeExternalRegistrationViewModel model)
        {
            // Lấy lại ProviderKey từ TempData hoặc từ model nếu bạn truyền ẩn
            // Tốt hơn là truyền ẩn qua model để đảm bảo nó không bị mất nếu TempData bị clear sớm
            // var loginProvider = TempData["ExternalLoginProvider"]?.ToString();
            // var providerKey = TempData["ExternalProviderKey"]?.ToString();
            // var providerDisplayName = TempData["ExternalProviderDisplayName"]?.ToString();
            // TempData.Keep("ExternalLoginProvider"); // Giữ lại nếu POST thất bại
            // TempData.Keep("ExternalProviderKey");
            // TempData.Keep("ExternalProviderDisplayName");

            // Kiểm tra lại model.LoginProvider và model.ProviderKey đã được gán từ hidden field trong form chưa
            if (string.IsNullOrEmpty(model.LoginProvider) || string.IsNullOrEmpty(model.ProviderKey))
            {
                ModelState.AddModelError(string.Empty, "Thông tin nhà cung cấp không hợp lệ. Vui lòng thử lại từ đầu.");
            }


            if (ModelState.IsValid)
            {
                // Kiểm tra lại xem email hoặc username có bị trùng không (phòng trường hợp người khác đăng ký trong lúc user này đang điền form)
                var existingUserByEmail = await _userManager.FindByEmailAsync(model.Email);
                if (existingUserByEmail != null)
                {
                    ModelState.AddModelError("Email", "Địa chỉ email này đã được sử dụng.");
                    return View(model);
                }

                var existingUserByUserName = await _userManager.FindByNameAsync(model.UserName);
                if (existingUserByUserName != null)
                {
                    ModelState.AddModelError("UserName", "Tên người dùng này đã được sử dụng.");
                    return View(model);
                }

                var user = new AppUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    EmailConfirmed = true, // Email từ external provider thường được coi là đã xác nhận
                    PhoneNumber = model.PhoneNumber,
                    // ZipCode = model.ZipCode, // Nếu bạn có trường này trong AppUser
                    // FullName = model.DisplayName, // Nếu bạn có trường FullName và muốn dùng DisplayName cho nó
                };

                var createUserResult = await _userManager.CreateAsync(user, model.Password);
                if (createUserResult.Succeeded)
                {
                    _logger?.LogInformation("User {UserName} created successfully from external login finalization.", user.UserName);

                    // Tạo lại ExternalLoginInfo để liên kết
                    var loginInfo = new ExternalLoginInfo(new ClaimsPrincipal(), model.LoginProvider, model.ProviderKey, model.ProviderDisplayName ?? model.LoginProvider);
                    var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);

                    if (addLoginResult.Succeeded)
                    {
                        _logger?.LogInformation("External login for {LoginProvider} linked to user {UserName}.", model.LoginProvider, user.UserName);
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        // (Tùy chọn) Gửi email chào mừng
                        // await _emailSender.SendWelcomeEmailAsync(user.Email, user.UserName);
                        TempData["SuccessMessage"] = "Chào mừng bạn đến với FishLoot! Tài khoản của bạn đã được tạo thành công.";
                        return LocalRedirect(model.ReturnUrl ?? Url.Content("~/"));
                    }
                    else
                    {
                        // Lỗi khi liên kết, có thể xóa user vừa tạo để tránh user mồ côi
                        _logger?.LogError("Failed to link external login {LoginProvider} for new user {UserName}. Deleting partial user. Errors: {Errors}", model.LoginProvider, user.UserName, string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
                        await _userManager.DeleteAsync(user); // Cố gắng dọn dẹp
                        AddErrors(addLoginResult);
                    }
                }
                else // CreateAsync thất bại
                {
                    AddErrors(createUserResult);
                }
            }

            // Nếu ModelState không hợp lệ hoặc có lỗi, hiển thị lại form
            // Đảm bảo các giá trị Provider được truyền lại cho view nếu cần
            // model.LoginProvider = loginProvider;
            // model.ProviderKey = providerKey;
            // model.ProviderDisplayName = providerDisplayName;
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous] // Cho phép truy cập khi chưa đăng nhập (vì đang trong quá trình đăng ký)
        public IActionResult CompleteRegistration(string email, string? userName = null, string? returnUrl = null)
        {
            // Lấy thông tin đã lưu từ TempData (đặc biệt là mật khẩu nếu bạn không yêu cầu nhập lại)
            var pendingEmail = TempData["PendingRegistrationEmail"]?.ToString();
            var pendingPassword = TempData["PendingRegistrationPassword"]?.ToString(); // Lấy mật khẩu đã lưu
            var pendingReturnUrl = TempData["PendingRegistrationReturnUrl"]?.ToString();
            // var pendingUserName = TempData["PendingRegistrationUserName"]?.ToString();

            // Giữ lại TempData để nếu POST thất bại và trả về View, nó vẫn còn cho lần submit sau
            TempData.Keep("PendingRegistrationEmail");
            TempData.Keep("PendingRegistrationPassword");
            TempData.Keep("PendingRegistrationReturnUrl");
            // TempData.Keep("PendingRegistrationUserName");

            if (string.IsNullOrEmpty(pendingEmail) || string.IsNullOrEmpty(pendingPassword) || pendingEmail != email)
            {
                // Nếu không có thông tin chờ xử lý hoặc email không khớp, không thể tiếp tục
                TempData["ErrorMessage"] = "Phiên đăng ký đã hết hạn hoặc không hợp lệ. Vui lòng bắt đầu lại.";
                return RedirectToAction(nameof(RegisterModal)); // Hoặc trang đăng ký chính
            }

            var model = new CompleteRegistrationViewModel
            {
                Email = pendingEmail,
                UserName = userName ?? pendingEmail.Split('@')[0], // Gợi ý UserName
                ReturnUrl = pendingReturnUrl,
                // PasswordToConfirm sẽ được người dùng nhập
            };
            return View(model); // Trả về Views/Account/CompleteRegistration.cshtml
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CompleteRegistration(CompleteRegistrationViewModel model)
        {
            // Lấy lại thông tin cốt lõi từ TempData (hoặc bạn có thể truyền chúng ẩn trong form)
            var originalEmail = TempData["PendingRegistrationEmail"]?.ToString();
            var originalPassword = TempData["PendingRegistrationPassword"]?.ToString(); // Password gốc từ bước 1
                                                                                        // model.ReturnUrl đã có từ form

            // Giữ lại TempData nếu có lỗi và cần hiển thị lại form
            TempData.Keep("PendingRegistrationEmail");
            TempData.Keep("PendingRegistrationPassword");
            TempData.Keep("PendingRegistrationReturnUrl");

            if (string.IsNullOrEmpty(originalEmail) || string.IsNullOrEmpty(originalPassword))
            {
                ModelState.AddModelError(string.Empty, "Phiên đăng ký không hợp lệ. Vui lòng thử lại.");
                return View(model);
            }
            if (originalEmail != model.Email) // Kiểm tra email không bị thay đổi
            {
                ModelState.AddModelError("Email", "Email không được thay đổi trong quá trình này.");
                return View(model);
            }

            // Validate lại mật khẩu người dùng nhập ở bước này với mật khẩu gốc
            if (model.PasswordToConfirm != originalPassword)
            {
                ModelState.AddModelError("PasswordToConfirm", "Mật khẩu và xác nhận mật khẩu không khớp.");
            }

            if (ModelState.IsValid)
            {
                var existingUserByEmail = await _userManager.FindByEmailAsync(model.Email);
                if (existingUserByEmail != null)
                {
                    ModelState.AddModelError("Email", "Địa chỉ email này đã được sử dụng.");
                    return View(model);
                }

                var existingUserByUserName = await _userManager.FindByNameAsync(model.UserName);
                if (existingUserByUserName != null)
                {
                    ModelState.AddModelError("UserName", "Tên người dùng này đã được sử dụng.");
                    return View(model);
                }

                var user = new AppUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    EmailConfirmed = false, // Sẽ gửi email xác nhận
                    PhoneNumber = model.PhoneNumber,
                    //Address = model.Address,
                    Gender = model.Gender,
                    DateOfBirth = model.DateOfBirth,
                    // ZipCode = model.ZipCode, // Nếu bạn dùng
                };

                // Sử dụng originalPassword (mật khẩu từ modal đăng ký) để tạo user
                var createUserResult = await _userManager.CreateAsync(user, originalPassword);
                if (createUserResult.Succeeded)
                {
                    _logger?.LogInformation("User {UserName} created successfully (pending email confirmation).", user.UserName);

                    // Gửi email xác nhận
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Action("ConfirmEmail", "Account",
                                    values: new { userId = user.Id, code = code, returnUrl = model.ReturnUrl },
                    protocol: Request.Scheme);                    bool emailSent = await _emailHelper.SendEmailConfirmationAsync(model.Email,
                        $"Vui lòng xác nhận tài khoản FishLoot của bạn bằng cách <a href='{HtmlEncoder.Default.Encode(callbackUrl ?? "")}'>nhấn vào đây</a>.");

                    if (!emailSent) { /* Xử lý lỗi gửi email nếu cần */ }

                    // Quyết định có đăng nhập người dùng ngay không hay đợi xác nhận email
                    if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        TempData["InfoMessage"] = "Đăng ký thành công! Vui lòng kiểm tra email để xác nhận tài khoản của bạn trước khi đăng nhập.";
                        return RedirectToAction("Index", "Home"); // Hoặc trang thông báo riêng
                    }
                    else
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        TempData["SuccessMessage"] = "Chào mừng bạn đến với FishLoot! Tài khoản của bạn đã được tạo thành công.";
                        return LocalRedirect(model.ReturnUrl ?? Url.Content("~/"));
                    }
                }
                else
                {
                    AddErrors(createUserResult);
                }
            }
            return View(model);        }        // ACTION QUẢN LÝ TÀI KHOẢN
        [HttpGet]
        public async Task<IActionResult> Manage(string? userId = null)
        {
            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null)
            {
                return NotFound("User not found");
            }

            AppUser targetUser;
            bool isViewingOwnProfile;

            // If userId is provided, we're viewing another user's profile
            if (!string.IsNullOrEmpty(userId) && userId != currentUser.Id)
            {
                targetUser = await _userManager.FindByIdAsync(userId);
                if (targetUser == null)
                {
                    return NotFound("Target user not found");
                }
                isViewingOwnProfile = false;
            }
            else
            {
                // Viewing own profile
                targetUser = currentUser;
                isViewingOwnProfile = true;
            }

            // Count restaurants owned by the target user using RestaurantService
            var restaurantCount = await _restaurantService.GetRestaurantCountByOwnerIdAsync(targetUser.Id);

            var model = new ManageAccountViewModel
            {
                Id = targetUser.Id,
                UserName = targetUser.UserName ?? "",
                Email = targetUser.Email ?? "",
                PhoneNumber = targetUser.PhoneNumber,
                Gender = targetUser.Gender,
                DateOfBirth = targetUser.DateOfBirth,
                TwoFactorEnabled = targetUser.TwoFactorEnabled,
                IsEmailConfirmed = targetUser.EmailConfirmed,
                RestaurantCount = restaurantCount,
                IsViewingOwnProfile = isViewingOwnProfile,
                StatusMessage = TempData["StatusMessage"]?.ToString()
            };

            return View(model);
        }        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Manage(ManageAccountViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found");
            }

            // Only allow editing own profile
            if (model.Id != user.Id)
            {
                return Forbid("You can only edit your own profile");
            }

            if (!ModelState.IsValid)
            {
                // Reload current values if validation fails
                model.TwoFactorEnabled = user.TwoFactorEnabled;
                model.IsEmailConfirmed = user.EmailConfirmed;
                model.IsViewingOwnProfile = true;
                return View(model);
            }

            bool hasChanges = false;

            // Update basic profile information
            if (user.PhoneNumber != model.PhoneNumber)
            {
                user.PhoneNumber = model.PhoneNumber;
                hasChanges = true;
            }

            if (user.Gender != model.Gender)
            {
                user.Gender = model.Gender;
                hasChanges = true;
            }

            if (user.DateOfBirth != model.DateOfBirth)
            {
                user.DateOfBirth = model.DateOfBirth;
                hasChanges = true;
            }

            // Update profile if there are changes
            if (hasChanges)
            {
                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    AddErrors(updateResult);
                    model.TwoFactorEnabled = user.TwoFactorEnabled;
                    model.IsEmailConfirmed = user.EmailConfirmed;
                    model.IsViewingOwnProfile = true;
                    return View(model);
                }
            }            TempData["StatusMessage"] = "Thông tin tài khoản đã được cập nhật thành công.";
            return RedirectToAction(nameof(Manage));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                // Return JSON for AJAX requests
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = false, message = "Dữ liệu không hợp lệ" });
                }
                TempData["StatusMessage"] = "Lỗi: Dữ liệu không hợp lệ";
                return RedirectToAction(nameof(Manage));
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = false, message = "Không tìm thấy người dùng" });
                }
                return NotFound("User not found");
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                var errorMessage = string.Join(", ", changePasswordResult.Errors.Select(e => e.Description));
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = false, message = errorMessage });
                }
                TempData["StatusMessage"] = $"Lỗi: {errorMessage}";
                return RedirectToAction(nameof(Manage));
            }

            await _signInManager.RefreshSignInAsync(user);
            
            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                return Json(new { success = true, message = "Mật khẩu đã được thay đổi thành công!" });
            }
            
            TempData["StatusMessage"] = "Mật khẩu đã được thay đổi thành công!";
            return RedirectToAction(nameof(Manage));
        }

        [HttpGet]
        public async Task<IActionResult> GetRestaurantReviews()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Json(new { success = false, message = "Không tìm thấy người dùng" });
            }

            // Get reviews for restaurants owned by the current user
            var reviews = await _context.Reviews
                .Include(r => r.User)
                .Include(r => r.Restaurant)
                .Include(r => r.Photos)
                .Where(r => r.Restaurant.OwnerId == user.Id)
                .OrderByDescending(r => r.ReviewDate)
                .Select(r => new
                {
                    Id = r.Id,
                    RestaurantName = r.Restaurant.Name,
                    UserName = r.User.UserName,
                    Rating = r.Rating,
                    Comment = r.Comment,
                    ReviewDate = r.ReviewDate.ToString("dd/MM/yyyy HH:mm"),
                    Photos = r.Photos.Select(p => new { Url = p.Url }).ToList()
                })
                .ToListAsync();

            return PartialView("_RestaurantReviewsPartial", reviews);
        }        [HttpGet]
        public async Task<IActionResult> GetMyRestaurants(int page = 1)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Json(new { success = false, message = "Không tìm thấy người dùng" });
            }

            try
            {
                // Get restaurants owned by the current user with pagination
                const int pageSize = 6; // Set appropriate page size for restaurant cards
                var restaurants = await _restaurantService.GetRestaurantByOwnerIdAsync(user.Id, page, pageSize);
                  // Convert to RestaurantCardViewModel for the partial view
                var restaurantCardViewModels = restaurants.Select(r => new PBL3.ViewModel.RestaurantCardViewModel
                {
                    Id = r.Id,
                    Name = r.Name,
                    Description = r.Description,
                    FullAddress = r.Address?.FullAddress ?? r.Address?.AddressLine1 ?? "Địa chỉ chưa cập nhật",
                    CardImageUrl = r.MainImageUrl,
                    AverageRating = r.AverageRating,
                    ReviewCount = r.ReviewCount,
                    Latitude = r.Address?.Latitude,
                    Longitude = r.Address?.Longitude,
                    MinTypicalPrice = r.MinTypicalPrice,
                    MaxTypicalPrice = r.MaxTypicalPrice,
                    Status = r.Status, // Add the missing Status property mapping
                    CuisineSummary = r.RestaurantCuisines?.Select(rc => rc.CuisineType?.Name).Where(name => !string.IsNullOrEmpty(name)).ToList() ?? new List<string?>()
                }).ToList();
                
                // Create a new paged list with the converted data
                var pagedResult = new X.PagedList.StaticPagedList<PBL3.ViewModel.RestaurantCardViewModel>(
                    restaurantCardViewModels,
                    restaurants.PageNumber,
                    restaurants.PageSize,
                    restaurants.TotalItemCount);
                
                return PartialView("_MyRestaurantsPartial", pagedResult);
            }
            catch (Exception)
            {
                return Json(new { success = false, message = "Có lỗi xảy ra khi tải danh sách nhà hàng" });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableTwoFactor()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found");
            }

            if (!user.EmailConfirmed)
            {
                TempData["StatusMessage"] = "Lỗi: Bạn cần xác nhận email trước khi có thể kích hoạt xác thực 2 bước.";
                return RedirectToAction(nameof(Manage));
            }

            var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
            if (result.Succeeded)
            {
                _logger?.LogInformation("User {UserId} enabled two factor authentication.", user.Id);
                TempData["StatusMessage"] = "Xác thực 2 bước đã được kích hoạt thành công. Bạn sẽ cần nhập mã xác thực từ email khi đăng nhập.";
            }
            else
            {
                TempData["StatusMessage"] = "Lỗi: Không thể kích hoạt xác thực 2 bước.";
            }

            return RedirectToAction(nameof(Manage));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DisableTwoFactor()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found");
            }

            var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (result.Succeeded)
            {
                _logger?.LogInformation("User {UserId} disabled two factor authentication.", user.Id);
                TempData["StatusMessage"] = "Xác thực 2 bước đã được tắt.";
            }
            else
            {
                TempData["StatusMessage"] = "Lỗi: Không thể tắt xác thực 2 bước.";
            }

            return RedirectToAction(nameof(Manage));
        }

        // Hàm tiện ích để thêm lỗi vào ModelState
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}