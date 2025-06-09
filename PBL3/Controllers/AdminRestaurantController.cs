using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PBL3.Models;
using PBL3.Services.Interfaces;
using System.Threading.Tasks;

namespace PBL3.Controllers
{
    public class AdminRestaurantController : AdminBaseController
    {
        private readonly IRestaurantService _restaurantService;
        private readonly UserManager<AppUser> _userManager;

        public AdminRestaurantController(IRestaurantService restaurantService, UserManager<AppUser> userManager)
        {
            _restaurantService = restaurantService;
            _userManager = userManager;
        }

        // GET: AdminRestaurant/Index
        public async Task<IActionResult> Index(string searchTerm, string statusFilter, string ownerSearchTerm, string sortBy, int pageNumber = 1, int pageSize = 10)
        {
            RestaurantStatus? status = null;
            if (Enum.TryParse<RestaurantStatus>(statusFilter, true, out RestaurantStatus parsedStatus))
            {
                status = parsedStatus;
            }

            ViewData["CurrentSearchTerm"] = searchTerm;
            ViewData["CurrentStatusFilter"] = statusFilter;
            ViewData["CurrentOwnerSearch"] = ownerSearchTerm;
            ViewData["CurrentSortBy"] = sortBy;


            var pagedResult = await _restaurantService.GetAllRestaurantsForAdminAsync(searchTerm, status, ownerSearchTerm, sortBy, pageNumber, pageSize);
            return View(pagedResult); // Cần tạo View Views/AdminRestaurant/Index.cshtml
        }

        // POST: AdminRestaurant/Approve/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Approve(int id)
        {
            if (id <= 0) return BadRequest("ID không hợp lệ.");
            var adminUserId = _userManager.GetUserId(User);
            var result = await _restaurantService.ApproveRestaurantAsync(id, adminUserId);
            if (result.Success) TempData["SuccessMessage"] = "Nhà hàng đã được duyệt.";
            else TempData["ErrorMessage"] = result.ErrorMessage ?? "Lỗi khi duyệt nhà hàng.";
            return RedirectToAction(nameof(Index));
        }

        // POST: AdminRestaurant/Reject/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Reject(int id, string reason = "Không đáp ứng tiêu chuẩn.") // Thêm input cho reason nếu cần
        {
            if (id <= 0) return BadRequest("ID không hợp lệ.");
            var adminUserId = _userManager.GetUserId(User);
            // Bạn có thể chọn một Status cụ thể cho "Rejected" hoặc dùng TemporarilyClosed
            var result = await _restaurantService.RejectOrDisableRestaurantAsync(id, reason, adminUserId, RestaurantStatus.TemporarilyClosed); // Hoặc một enum status "Rejected" mới
            if (result.Success) TempData["SuccessMessage"] = "Nhà hàng đã được từ chối/vô hiệu hóa.";
            else TempData["ErrorMessage"] = result.ErrorMessage ?? "Lỗi khi xử lý nhà hàng.";
            return RedirectToAction(nameof(Index));
        }

        // POST: AdminRestaurant/Suspend/5 (Ví dụ dùng chung với RejectOrDisable)
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Suspend(int id, string reason = "Tạm ngưng hoạt động do vi phạm.")
        {
            if (id <= 0) return BadRequest("ID không hợp lệ.");
            var adminUserId = _userManager.GetUserId(User);
            var result = await _restaurantService.RejectOrDisableRestaurantAsync(id, reason, adminUserId, RestaurantStatus.TemporarilyClosed);
            if (result.Success) TempData["SuccessMessage"] = "Nhà hàng đã được tạm ngưng.";
            else TempData["ErrorMessage"] = result.ErrorMessage ?? "Lỗi khi tạm ngưng nhà hàng.";
            return RedirectToAction(nameof(Index));
        }


        // POST: AdminRestaurant/Unsuspend/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Unsuspend(int id)
        {
            if (id <= 0) return BadRequest("ID không hợp lệ.");
            var adminUserId = _userManager.GetUserId(User);
            var result = await _restaurantService.UnsuspendRestaurantAsync(id, adminUserId);
            if (result.Success) TempData["SuccessMessage"] = "Nhà hàng đã được mở lại.";
            else TempData["ErrorMessage"] = result.ErrorMessage ?? "Lỗi khi mở lại nhà hàng.";
            return RedirectToAction(nameof(Index));
        }

        // GET: AdminRestaurant/Edit/5 (Sẽ cần EditRestaurantViewModel và View riêng)
        // public async Task<IActionResult> Edit(int id) { /* ... */ }
        // POST: AdminRestaurant/Edit/5
        // public async Task<IActionResult> Edit(EditRestaurantViewModel model) { /* ... */ }
    }
}
