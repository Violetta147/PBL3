// Controllers/AdminUserController.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // Cho ToListAsync
using PBL3.Models;
using PBL3.ViewModel.Admin; // Tạo namespace này cho ViewModel của Admin
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic; // Cho List
using PBL3.Models.Common;

namespace PBL3.Controllers
{
    public class AdminUserController : AdminBaseController // Kế thừa từ AdminBaseController
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AdminUserController> _logger;
        // private readonly ApplicationDbContext _context; // Chỉ inject nếu thực sự cần

        public AdminUserController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, ILogger<AdminUserController> logger /*, ApplicationDbContext context */)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            // _context = context;
            _logger = logger;
        }

        // GET: AdminUser hoặc AdminUser/Index
        public async Task<IActionResult> Index(string searchTerm, int pageNumber = 1, int pageSize = 10)
        {
            // Logic lấy danh sách user sẽ được thêm vào đây
            ViewData["CurrentFilter"] = searchTerm;
            ViewData["CurrentPage"] = pageNumber;
            // TempData["Message"] = "Trang quản lý người dùng đang được xây dựng.";
            // return View(new List<UserListItemViewModel>()); // Trả về danh sách rỗng ban đầu

            IQueryable<AppUser> usersQuery = _userManager.Users.OrderBy(u => u.UserName);

            if (!string.IsNullOrEmpty(searchTerm))
            {
                usersQuery = usersQuery.Where(u => u.UserName.Contains(searchTerm) ||
                                                   (u.Email != null && u.Email.Contains(searchTerm)) ||
                                                   (u.DisplayName != null && u.DisplayName.Contains(searchTerm)));
            }

            var totalUsers = await usersQuery.CountAsync();
            var users = await usersQuery
                                .Skip((pageNumber - 1) * pageSize)
                                .Take(pageSize)
                                .ToListAsync();

            var userViewModels = new List<UserListItemViewModel>();
            foreach (var user in users)
            {
                userViewModels.Add(new UserListItemViewModel
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    DisplayName = user.DisplayName,
                    Roles = await _userManager.GetRolesAsync(user), // Lấy danh sách vai trò
                    IsLockedOut = await _userManager.IsLockedOutAsync(user),
                    LockoutEnd = user.LockoutEnd,
                    EmailConfirmed = user.EmailConfirmed
                });
            }

            var pagedResult = new PagedResult<UserListItemViewModel>
            {
                Items = userViewModels,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalCount = totalUsers
            };

            return View(pagedResult);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockoutUser(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                TempData["ErrorMessage"] = "ID người dùng không được cung cấp.";
                return RedirectToAction(nameof(Index));
            }

            var userToLock = await _userManager.FindByIdAsync(id);
            if (userToLock == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy người dùng.";
                return RedirectToAction(nameof(Index));
            }

            // Không cho Admin tự khóa chính mình (tùy chọn, nhưng là một biện pháp an toàn)
            var currentAdminId = _userManager.GetUserId(User);
            if (userToLock.Id == currentAdminId)
            {
                TempData["ErrorMessage"] = "Bạn không thể tự khóa tài khoản của chính mình.";
                return RedirectToAction(nameof(Index));
            }

            // Kiểm tra xem user có phải là Admin không, không cho khóa Admin khác (tùy chính sách)
            if (await _userManager.IsInRoleAsync(userToLock, "Admin"))
            {
                // Nếu bạn muốn cho phép admin khóa admin khác, hãy bỏ điều kiện này
                // Hoặc thêm logic kiểm tra quyền cao hơn nếu cần
                TempData["ErrorMessage"] = "Không thể khóa tài khoản của quản trị viên khác.";
                return RedirectToAction(nameof(Index));
            }


            // Đặt LockoutEnd thành một ngày trong tương lai rất xa để khóa vô thời hạn
            // Hoặc bạn có thể cho phép Admin chọn thời gian khóa cụ thể
            var lockoutEndDate = DateTimeOffset.MaxValue; // Khóa vĩnh viễn (cho đến khi được mở khóa thủ công)
            // Hoặc ví dụ khóa trong 7 ngày:
            // var lockoutEndDate = DateTimeOffset.UtcNow.AddDays(7);

            var result = await _userManager.SetLockoutEndDateAsync(userToLock, lockoutEndDate);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {UserName} (ID: {UserId}) was locked out by Admin {AdminUserName}.", userToLock.UserName, userToLock.Id, User.Identity.Name);
                TempData["SuccessMessage"] = $"Tài khoản '{userToLock.UserName}' đã được khóa.";
            }
            else
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Failed to lock out user {UserName} (ID: {UserId}). Errors: {Errors}", userToLock.UserName, userToLock.Id, errors);
                TempData["ErrorMessage"] = $"Không thể khóa tài khoản '{userToLock.UserName}'. Lỗi: {errors}";
            }

            return RedirectToAction(nameof(Index), new { searchTerm = ViewData["CurrentFilter"], pageNumber = ViewData["CurrentPage"] });
        }

        // POST: AdminUser/UnlockUser/some-user-id
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UnlockUser(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                TempData["ErrorMessage"] = "ID người dùng không được cung cấp.";
                return RedirectToAction(nameof(Index));
            }

            var userToUnlock = await _userManager.FindByIdAsync(id);
            if (userToUnlock == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy người dùng.";
                return RedirectToAction(nameof(Index));
            }

            // Set LockoutEnd thành null hoặc một thời điểm trong quá khứ để mở khóa
            var result = await _userManager.SetLockoutEndDateAsync(userToUnlock, null); // Hoặc DateTimeOffset.MinValue

            if (result.Succeeded)
            {
                // Cũng nên reset AccessFailedCount
                await _userManager.ResetAccessFailedCountAsync(userToUnlock);
                _logger.LogInformation("User {UserName} (ID: {UserId}) was unlocked by Admin {AdminUserName}.", userToUnlock.UserName, userToUnlock.Id, User.Identity.Name);
                TempData["SuccessMessage"] = $"Tài khoản '{userToUnlock.UserName}' đã được mở khóa.";
            }
            else
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Failed to unlock user {UserName} (ID: {UserId}). Errors: {Errors}", userToUnlock.UserName, userToUnlock.Id, errors);
                TempData["ErrorMessage"] = $"Không thể mở khóa tài khoản '{userToUnlock.UserName}'. Lỗi: {errors}";
            }

            return RedirectToAction(nameof(Index), new { searchTerm = ViewData["CurrentFilter"], pageNumber = ViewData["CurrentPage"] });
        }

        // GET: AdminUser/EditRoles/some-user-id
        [HttpGet]
        public async Task<IActionResult> EditRoles(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound("ID người dùng không được cung cấp.");
            }

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy người dùng.";
                return RedirectToAction(nameof(Index));
            }

            // Không cho Admin tự sửa vai trò của chính mình (để tránh mất quyền Admin duy nhất)
            var currentAdminId = _userManager.GetUserId(User);
            if (user.Id == currentAdminId && await _userManager.IsInRoleAsync(user, "Admin"))
            {
                var adminCount = (await _userManager.GetUsersInRoleAsync("Admin")).Count;
                if (adminCount <= 1)
                {
                    TempData["ErrorMessage"] = "Không thể bỏ vai trò Admin của quản trị viên duy nhất.";
                    return RedirectToAction(nameof(Index));
                }
            }


            var userRoles = await _userManager.GetRolesAsync(user);
            var allRoles = await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync();

            var model = new UserEditRolesViewModel
            {
                UserId = user.Id,
                UserName = user.UserName,
                DisplayName = user.DisplayName,
                Roles = allRoles.Select(role => new SelectableRoleViewModel
                {
                    RoleId = role.Id,
                    RoleName = role.Name,
                    IsSelected = userRoles.Contains(role.Name)
                }).ToList(),
                SelectedRoleNames = userRoles.ToList() // Khởi tạo để form có thể bind khi POST
            };

            ViewData["UserNameForEdit"] = user.UserName; // Để hiển thị trên tiêu đề trang
            return View(model);
        }

        // POST: AdminUser/EditRoles
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditRoles(UserEditRolesViewModel model)
        {
            // ModelState.Remove(nameof(model.Roles)); // Roles không được POST về, chỉ SelectedRoleNames
            // ModelState.Remove(nameof(model.UserName));
            // ModelState.Remove(nameof(model.DisplayName));

            // Thay vì Remove, chúng ta chỉ validate những gì cần thiết hoặc có một ViewModel riêng cho POST
            // Hiện tại, nếu SelectedRoleNames là null thì có thể do không có role nào được chọn
            model.SelectedRoleNames ??= new List<string>(); // Đảm bảo không null

            // if (!ModelState.IsValid) // ViewModel này đơn giản, có thể không cần check phức tạp
            // {
            //     // Populate lại Roles list nếu cần
            //     return View(model);
            // }

            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy người dùng.";
                return RedirectToAction(nameof(Index));
            }

            // Không cho Admin tự gỡ vai trò Admin của chính mình nếu là Admin cuối cùng
            var currentAdminId = _userManager.GetUserId(User);
            bool isEditingSelf = user.Id == currentAdminId;
            bool wasAdmin = await _userManager.IsInRoleAsync(user, "Admin");
            bool willBeAdmin = model.SelectedRoleNames.Contains("Admin");

            if (isEditingSelf && wasAdmin && !willBeAdmin)
            {
                var adminCount = (await _userManager.GetUsersInRoleAsync("Admin")).Count;
                if (adminCount <= 1)
                {
                    TempData["ErrorMessage"] = "Không thể tự gỡ bỏ vai trò Admin của quản trị viên duy nhất.";
                    // Populate lại model.Roles và trả về View
                    var allRoles = await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync();
                    model.Roles = allRoles.Select(role => new SelectableRoleViewModel
                    {
                        RoleId = role.Id,
                        RoleName = role.Name,
                        IsSelected = model.SelectedRoleNames.Contains(role.Name) // Giữ lại lựa chọn người dùng
                    }).ToList();
                    ViewData["UserNameForEdit"] = user.UserName;
                    return View(model);
                }
            }


            var userCurrentRoles = await _userManager.GetRolesAsync(user);

            // Xóa các vai trò cũ không còn được chọn
            var rolesToRemove = userCurrentRoles.Except(model.SelectedRoleNames).ToList();
            if (rolesToRemove.Any())
            {
                var removeResult = await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
                if (!removeResult.Succeeded)
                {
                    ModelState.AddModelError("", "Lỗi khi xóa vai trò cũ: " + string.Join(", ", removeResult.Errors.Select(e => e.Description)));
                    // Populate lại model.Roles và trả về View
                    var allRoles = await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync();
                    model.Roles = allRoles.Select(role => new SelectableRoleViewModel { /*...*/ IsSelected = model.SelectedRoleNames.Contains(role.Name) }).ToList();
                    ViewData["UserNameForEdit"] = user.UserName;
                    return View(model);
                }
            }

            // Thêm các vai trò mới được chọn
            var rolesToAdd = model.SelectedRoleNames.Except(userCurrentRoles).ToList();
            if (rolesToAdd.Any())
            {
                var addResult = await _userManager.AddToRolesAsync(user, rolesToAdd);
                if (!addResult.Succeeded)
                {
                    ModelState.AddModelError("", "Lỗi khi thêm vai trò mới: " + string.Join(", ", addResult.Errors.Select(e => e.Description)));
                    // Populate lại model.Roles và trả về View
                    var allRoles = await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync();
                    model.Roles = allRoles.Select(role => new SelectableRoleViewModel { /*...*/ IsSelected = model.SelectedRoleNames.Contains(role.Name) }).ToList();
                    ViewData["UserNameForEdit"] = user.UserName;
                    return View(model);
                }
            }

            _logger.LogInformation("Roles updated for user {UserName} (ID: {UserId}) by Admin {AdminUserName}.", user.UserName, user.Id, User.Identity.Name);
            TempData["SuccessMessage"] = $"Vai trò cho người dùng '{user.UserName}' đã được cập nhật.";
            return RedirectToAction(nameof(Index));
        }
    }
}