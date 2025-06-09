using PBL3.Models;
using PBL3.ViewModel; // Hoặc namespace chứa CreateUserViewModel của bạn
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PBL3.Ultilities; // Namespace chứa EmailHelper/IEmailSender
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities; // Cho WebEncoders
using System.Text;                 // Cho Encoding
using System.Text.Encodings.Web;   // Cho HtmlEncoder
using Microsoft.Extensions.Logging; // (Tùy chọn) Cho logging

namespace PBL3.Controllers
{
    // [Authorize(Roles = "Admin")] // Bạn nên thêm phân quyền cho AdminController
    public class AdminController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IPasswordHasher<AppUser> _passwordHasher;
        private readonly IPasswordValidator<AppUser> _passwordValidator;
        private readonly IUserValidator<AppUser> _userValidator;
        private readonly IEmailSender _emailSender; // Inject IEmailSender
        private readonly ILogger<AdminController> _logger; // (Tùy chọn) Inject ILogger

        public AdminController(
            UserManager<AppUser> userManager,
            IPasswordHasher<AppUser> passwordHash,
            IPasswordValidator<AppUser> passwordValidator,
            IUserValidator<AppUser> userValidator,
            IEmailSender emailSender, // Thêm vào constructor
            ILogger<AdminController> logger = null) // Logger là tùy chọn
        {
            _userManager = userManager;
            _passwordHasher = passwordHash;
            _passwordValidator = passwordValidator;
            _userValidator = userValidator;
            _emailSender = emailSender; // Gán giá trị
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View(_userManager.Users);
        }

        public ViewResult Create() => View(new CreateUserViewModel()); // Trả về ViewModel rỗng

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateUserViewModel model) // Sử dụng CreateUserViewModel
        {
            if (ModelState.IsValid)
            {
                AppUser appUser = new AppUser
                {
                    UserName = model.Name, // Hoặc model.Email nếu bạn muốn UserName là Email
                    Email = model.Email,
                    EmailConfirmed = false, // Mặc định là false, cần xác nhận
                    TwoFactorEnabled = true // Thường thì người dùng tự bật 2FA sau khi đăng nhập
                };

                IdentityResult result = await _userManager.CreateAsync(appUser, model.Password);

                if (result.Succeeded)
                {
                    _logger?.LogInformation($"User {appUser.Email} created successfully by admin.");

                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);
                    var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                    var confirmationLink = Url.Action(
                        action: "ConfirmEmail",
                        controller: "Account", // Giả sử action ConfirmEmail nằm trong AccountController
                        values: new { userId = appUser.Id, code = encodedToken },
                        protocol: Request.Scheme);

                    if (string.IsNullOrEmpty(confirmationLink))
                    {
                        _logger?.LogError("Could not generate confirmation link for user {Email}", appUser.Email);
                        ModelState.AddModelError("", "Lỗi khi tạo link xác nhận email.");
                        // Không nên dừng ở đây, tài khoản đã được tạo, chỉ là email chưa gửi được
                    }
                    else
                    {
                        string emailSubject = "Xác nhận tài khoản của bạn - Được tạo bởi Quản trị viên";
                        string emailBody = $"Chào {appUser.UserName},<br><br>" +
                                           $"Một tài khoản đã được tạo cho bạn trên hệ thống của chúng tôi bởi quản trị viên.<br>" +
                                           $"Vui lòng xác nhận địa chỉ email của bạn bằng cách nhấn vào liên kết sau: <a href='{HtmlEncoder.Default.Encode(confirmationLink)}'>Xác nhận Email</a>.<br><br>" +
                                           "Nếu bạn không yêu cầu tạo tài khoản này, vui lòng bỏ qua email này.<br><br>" +
                                           "Trân trọng,<br>" +
                                           "Đội ngũ Quản trị.";

                        bool emailSent = await _emailSender.SendGenericEmailAsync(appUser.Email, emailSubject, emailBody);

                        if (emailSent)
                        {
                            TempData["SuccessMessage"] = $"Tài khoản cho {appUser.Email} đã được tạo và email xác nhận đã được gửi.";
                        }
                        else
                        {
                            _logger?.LogWarning($"Failed to send confirmation email to {appUser.Email} after admin creation.");
                            TempData["WarningMessage"] = $"Tài khoản cho {appUser.Email} đã được tạo, NHƯNG có lỗi khi gửi email xác nhận. Người dùng có thể cần xác nhận thủ công hoặc thử lại.";
                        }
                    }
                    return RedirectToAction("Index");
                }
                else
                {
                    _logger?.LogError("Admin failed to create user {Email}. Errors: {Errors}", model.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                    foreach (IdentityError error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }
            // Nếu ModelState không hợp lệ, quay lại view Create với các lỗi và dữ liệu đã nhập
            return View(model);
        }

        public async Task<IActionResult> Update(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();
            AppUser user = await _userManager.FindByIdAsync(id);
            if (user != null)
            {
                // Tạo một ViewModel để chỉnh sửa, không nên truyền trực tiếp AppUser vào View
                var model = new EditUserViewModel // Cần tạo ViewModel này
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    EmailConfirmed = user.EmailConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled
                    // Không bao gồm PasswordHash
                };
                return View(model);
            }
            else
            {
                TempData["ErrorMessage"] = "Không tìm thấy người dùng.";
                return RedirectToAction("Index");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(EditUserViewModel model) // Sử dụng EditUserViewModel
        {
            if (!ModelState.IsValid) return View(model);

            AppUser user = await _userManager.FindByIdAsync(model.Id);
            if (user == null)
            {
                ModelState.AddModelError("", "Không tìm thấy người dùng.");
                return View(model);
            }

            // Validate và cập nhật Email nếu có thay đổi
            if (user.Email != model.Email && !string.IsNullOrEmpty(model.Email))
            {
                var setEmailResult = await _userManager.SetEmailAsync(user, model.Email);
                if (!setEmailResult.Succeeded)
                {
                    Errors(setEmailResult);
                    return View(model); // Trả về với lỗi
                }
                // Nếu email thay đổi, có thể cần đặt lại EmailConfirmed = false và gửi lại email xác nhận
                // user.EmailConfirmed = false; // Tùy theo logic của bạn
            }
            else if (string.IsNullOrEmpty(model.Email))
            {
                ModelState.AddModelError(nameof(model.Email), "Email không được để trống.");
                return View(model);
            }


            // Validate và cập nhật UserName nếu có thay đổi
            if (user.UserName != model.UserName && !string.IsNullOrEmpty(model.UserName))
            {
                var setUserNameResult = await _userManager.SetUserNameAsync(user, model.UserName);
                if (!setUserNameResult.Succeeded)
                {
                    Errors(setUserNameResult);
                    return View(model);
                }
            }
            else if (string.IsNullOrEmpty(model.UserName))
            {
                ModelState.AddModelError(nameof(model.UserName), "Tên người dùng không được để trống.");
                return View(model);
            }

            // Cập nhật các thuộc tính khác
            user.EmailConfirmed = model.EmailConfirmed; // Cho phép admin thay đổi trạng thái xác nhận
            user.TwoFactorEnabled = model.TwoFactorEnabled;


            // Thay đổi mật khẩu nếu được cung cấp
            if (!string.IsNullOrEmpty(model.NewPassword))
            {
                var passwordValidationResult = await _passwordValidator.ValidateAsync(_userManager, user, model.NewPassword);
                if (passwordValidationResult.Succeeded)
                {
                    user.PasswordHash = _passwordHasher.HashPassword(user, model.NewPassword);
                }
                else
                {
                    Errors(passwordValidationResult);
                    // Không dừng lại ở đây nếu các thay đổi khác hợp lệ, chỉ báo lỗi mật khẩu
                }
            }

            // Chỉ cập nhật nếu không có lỗi nghiêm trọng từ việc thay đổi email/username
            if (ModelState.ErrorCount == 0 || !ModelState.Values.Any(v => v.Errors.Any(e => e.ErrorMessage.Contains("Email") || e.ErrorMessage.Contains("Tên người dùng"))))
            {
                IdentityResult result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    TempData["SuccessMessage"] = $"Thông tin người dùng {user.UserName} đã được cập nhật.";
                    return RedirectToAction("Index");
                }
                else
                {
                    Errors(result);
                }
            }


            return View(model); // Trả về view với model và các lỗi (nếu có)
        }


        private void Errors(IdentityResult result)
        {
            foreach (IdentityError error in result.Errors)
                ModelState.AddModelError("", error.Description);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id)) return BadRequest("ID người dùng không hợp lệ.");

            AppUser user = await _userManager.FindByIdAsync(id);
            if (user != null)
            {
                // Cân nhắc: Không nên cho phép admin xóa tài khoản của chính mình
                // var currentUser = await _userManager.GetUserAsync(User);
                // if (currentUser != null && currentUser.Id == user.Id) {
                //     ModelState.AddModelError("", "Bạn không thể xóa tài khoản của chính mình.");
                //     return View("Index", _userManager.Users);
                // }

                IdentityResult result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    TempData["SuccessMessage"] = $"Người dùng {user.UserName} đã được xóa.";
                    return RedirectToAction("Index");
                }
                else
                {
                    Errors(result);
                    TempData["ErrorMessage"] = $"Lỗi khi xóa người dùng {user.UserName}.";
                }
            }
            else
            {
                TempData["ErrorMessage"] = "Không tìm thấy người dùng để xóa.";
            }
            // Nếu có lỗi, quay lại trang Index và hiển thị TempData
            return RedirectToAction("Index");
        }

        // Đặt action này trong một Controller phù hợp, ví dụ AdminController
        // Đảm bảo action này được bảo vệ kỹ lưỡng, chỉ admin cấp cao nhất mới có quyền truy cập.
        // Có thể thêm một tham số xác nhận mạnh mẽ (ví dụ: yêu cầu nhập một chuỗi đặc biệt)
        // để tránh vô tình kích hoạt.

        // [Authorize(Roles = "SuperAdminOnly")] // Ví dụ về phân quyền cực mạnh
        [HttpPost]
        [ValidateAntiForgeryToken] // Quan trọng!
        public async Task<IActionResult> DeleteAllUsers(string confirmationPassword) // Thêm một bước xác nhận
        {
            // THÊM MỘT CƠ CHẾ XÁC NHẬN MẠNH MẼ Ở ĐÂY
            // Ví dụ: Kiểm tra xem confirmationPassword có khớp với một giá trị bí mật không
            // Hoặc yêu cầu nhiều bước xác nhận.
            // ĐÂY CHỈ LÀ VÍ DỤ ĐƠN GIẢN, BẠN CẦN LÀM CHO NÓ AN TOÀN HƠN.
            if (confirmationPassword != "DELETE_ALL_MY_USERS_NOW_PLEASE_IM_SURE_12345")
            {
                TempData["ErrorMessage"] = "Xác nhận xóa toàn bộ người dùng không hợp lệ. Thao tác đã bị hủy.";
                _logger?.LogWarning("Attempt to delete all users with invalid confirmation.");
                return RedirectToAction("Index", "Admin"); // Hoặc một trang cài đặt nào đó
            }

            _logger?.LogWarning("!!! ATTEMPTING TO DELETE ALL USERS !!! Confirmation provided.");

            var allUsers = _userManager.Users.ToList(); // Lấy danh sách tất cả người dùng
            int successCount = 0;
            int failCount = 0;
            List<string> errorMessages = new List<string>();

            if (!allUsers.Any())
            {
                TempData["InfoMessage"] = "Không có người dùng nào trong hệ thống để xóa.";
                return RedirectToAction("Index", "Admin");
            }

            foreach (var user in allUsers)
            {
                // (Tùy chọn) Bỏ qua việc xóa một số tài khoản admin cố định nếu cần
                // if (user.UserName == "superadmin" || user.Email == "admin_cannot_be_deleted@example.com")
                // {
                //     _logger?.LogInformation("Skipping deletion of protected user: {UserName}", user.UserName);
                //     continue;
                // }

                IdentityResult result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    successCount++;
                    _logger?.LogInformation("Successfully deleted user: {UserId} - {UserName}", user.Id, user.UserName);
                }
                else
                {
                    failCount++;
                    string errors = string.Join(", ", result.Errors.Select(e => $"{e.Code}: {e.Description}"));
                    _logger?.LogError("Failed to delete user: {UserId} - {UserName}. Errors: {Errors}", user.Id, user.UserName, errors);
                    errorMessages.Add($"Lỗi khi xóa {user.UserName}: {errors}");
                }
            }

            TempData["SuccessMessage"] = $"Đã xóa thành công {successCount} người dùng.";
            if (failCount > 0)
            {
                TempData["ErrorMessage"] = $"Không thể xóa {failCount} người dùng. Vui lòng kiểm tra logs để biết chi tiết. Lỗi ví dụ: {errorMessages.FirstOrDefault()}";
                // Có thể lưu errorMessages vào một nơi khác nếu quá dài cho TempData
            }

            _logger?.LogWarning("!!! FINISHED DELETING ALL USERS !!! Success: {SuccessCount}, Failed: {FailCount}", successCount, failCount);

            // Sau khi xóa hết, có thể bạn muốn đăng xuất admin hiện tại nếu tài khoản của họ cũng bị xóa
            // await _signInManager.SignOutAsync();
            // return RedirectToAction("Index", "Home"); // Chuyển về trang chủ

            return RedirectToAction("Index", "Admin");
        }
    }
}