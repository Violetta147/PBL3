// PBL3.Controllers.BusinessController.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using PBL3.Models;
using PBL3.Services.Interfaces;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using PBL3.ViewModel.Restaurant;
using PBL3.Services.Implementations;
using Microsoft.EntityFrameworkCore;
using PBL3.ViewModel.Menu;

namespace PBL3.Controllers
{
    [Authorize]
    public class BusinessController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IRestaurantService _restaurantService;
        private readonly ICuisineTypeService _cuisineTypeService;
        private readonly ITagService _tagService;
        private readonly IMenuService _menuService;
        private readonly ILogger<BusinessController> _logger;
        public BusinessController(
            UserManager<AppUser> userManager,
            IRestaurantService restaurantService,
            ICuisineTypeService cuisineTypeService,
            ITagService tagService,
            IMenuService imenuService,
            ILogger<BusinessController> logger)
        {
            _userManager = userManager;
            _restaurantService = restaurantService;
            _cuisineTypeService = cuisineTypeService;
            _tagService = tagService;
            _menuService = imenuService;
            _logger = logger;
        }

        // GET: /Business/Register
        [HttpGet]
        public async Task<IActionResult> Register()
        {
            var viewModel = new RegisterRestaurantViewModel();
            await PopulateAvailableOptionsAsync(viewModel); // Gọi hàm helper mới
            return View(viewModel);
        }

        // POST: /Business/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterRestaurantViewModel model)
        {
            // SelectedCuisineTypeIds và SelectedTagIds sẽ tự động được bind từ form
            // nếu các checkbox trong View có name="SelectedCuisineTypeIds" và name="SelectedTagIds"

            if (!ModelState.IsValid)
            {
                await PopulateAvailableOptionsAsync(model); // Populate lại và giữ lựa chọn
                return View(model);
            }

            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null)
            {
                // Không nên xảy ra với [Authorize]
                ModelState.AddModelError("", "Không thể xác định người dùng hiện tại.");
                await PopulateAvailableOptionsAsync(model);
                return View(model);
            }

            var creationResult = await _restaurantService.CreateRestaurantAsync(model, currentUser.Id);

            if (creationResult.Success)
            {
                TempData["SuccessMessage"] = $"Nhà hàng '{model.Name}' đã được đăng ký thành công!";
                // Có thể redirect đến trang chi tiết nhà hàng vừa tạo nếu muốn
                // return RedirectToAction("Details", "Restaurants", new { id = creationResult.CreatedRestaurantId });
                return RedirectToAction(nameof(MyRestaurants));
            }
            else
            {
                ModelState.AddModelError(string.Empty, creationResult.ErrorMessage ?? "Đã có lỗi xảy ra khi đăng ký nhà hàng.");
                await PopulateAvailableOptionsAsync(model);
                return View(model);
            }
        }

        // GET: /Business/MyRestaurants
        [HttpGet]
        public async Task<IActionResult> MyRestaurants()
        {
            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null)
            {
                return Challenge();
            }

            var myRestaurantsViewModel = await _restaurantService.GetRestaurantsByOwnerIdAsync(currentUser.Id);

            ViewData["UserDisplayName"] = currentUser.DisplayName ?? currentUser.UserName;

            return View(myRestaurantsViewModel);
        }

        [HttpGet]
        public async Task<IActionResult> EditRestaurant(int? id)
        {
            if (id == null)
            {
                return NotFound("ID nhà hàng không được cung cấp.");
            }

            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null)
            {
                // Điều này không nên xảy ra nếu action được bảo vệ bởi [Authorize]
                return Challenge(); // Hoặc RedirectToAction("Login", "Account");
            }

            var viewModel = await _restaurantService.GetRestaurantForEditAsync(id.Value, currentUser.Id);

            if (viewModel == null)
            {
                // Lý do có thể là nhà hàng không tồn tại, hoặc người dùng không phải chủ sở hữu
                // Service đã log chi tiết, ở đây chỉ cần trả về NotFound hoặc Forbid
                // Nếu muốn phân biệt rõ, GetRestaurantForEditAsync có thể trả về một enum trạng thái
                TempData["ErrorMessage"] = "Không tìm thấy nhà hàng hoặc bạn không có quyền chỉnh sửa.";
                return RedirectToAction(nameof(MyRestaurants));
            }

            // Populate lại AvailableCuisineTypes và AvailableTags cho dropdown/checkboxes
            // Service đã làm việc này trong GetRestaurantForEditAsync rồi.
            // Nếu service không làm, bạn sẽ làm ở đây:
            // await PopulateAvailableOptionsAsync(viewModel); // Giả sử viewModel là EditRestaurantViewModel

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditRestaurant(int id, EditRestaurantViewModel model)
        {
            if (id != model.Id) // Kiểm tra ID từ route và ID từ model có khớp không
            {
                return BadRequest("Dữ liệu không hợp lệ.");
            }

            // Lấy lại danh sách available options nếu ModelState không hợp lệ để trả về view
            // vì chúng không được POST về cùng với model.
            if (!ModelState.IsValid)
            {
                // Cần populate lại AvailableCuisineTypes và AvailableTags cho model trước khi trả về View
                await PopulateAvailableOptionsForEditAsync(model); // Hàm helper mới hoặc điều chỉnh hàm cũ
                return View(model);
            }

            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null)
            {
                ModelState.AddModelError("", "Không thể xác định người dùng hiện tại.");
                await PopulateAvailableOptionsForEditAsync(model);
                return View(model);
            }

            var updateResult = await _restaurantService.UpdateRestaurantAsync(model, currentUser.Id);

            if (updateResult.Success)
            {
                TempData["SuccessMessage"] = $"Thông tin nhà hàng '{model.Name}' đã được cập nhật thành công!";
                return RedirectToAction(nameof(MyRestaurants)); // Hoặc RedirectToAction("Details", "Restaurants", new { id = model.Id });
            }
            else
            {
                ModelState.AddModelError(string.Empty, updateResult.ErrorMessage ?? "Đã có lỗi xảy ra khi cập nhật nhà hàng.");
                await PopulateAvailableOptionsForEditAsync(model);
                return View(model);
            }
        }

        [HttpGet]
        public async Task<IActionResult> ManageMenu(int id) // Đổi tên tham số thành "id"
        {
            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Challenge();
            }

            // Truyền "id" (là restaurantId) vào service
            var viewModel = await _menuService.GetRestaurantMenuForManagementAsync(id, ownerId);

            if (viewModel == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy thông tin thực đơn hoặc bạn không có quyền truy cập.";
                return RedirectToAction(nameof(MyRestaurants));
            }
            ViewBag.RestaurantId = id; // Giữ lại để truyền cho các nút tạo mới trong ManageMenu.cshtml
            return View(viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> GetCreateMenuForm(int restaurantId)
        {
            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId)) return Unauthorized(); // Hoặc Challenge()

            var validationResult = await _restaurantService.ValidateRestaurantOwnershipAsync(restaurantId, ownerId);

            if (!validationResult.IsValid)
            {
                _logger.LogWarning("User {OwnerId} attempted to access GetCreateMenuForm for unowned/non-existent restaurant ID {RestaurantId}.", ownerId, restaurantId);
                return PartialView("_ErrorModalPartial", "Không tìm thấy nhà hàng hoặc bạn không có quyền tạo thực đơn cho nhà hàng này.");
            }

            var viewModel = new MenuEditViewModel
            {
                RestaurantId = restaurantId,
                RestaurantName = validationResult.RestaurantName, // Lấy tên từ kết quả validate
                IsActive = true
            };
            return PartialView("_MenuFormPartial", viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> GetEditMenuForm(int menuId)
        {
            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId)) return Unauthorized();

            // _menuService.GetMenuForEditAsync đã bao gồm kiểm tra quyền sở hữu bên trong nó
            var viewModel = await _menuService.GetMenuForEditAsync(menuId, ownerId);

            if (viewModel == null)
            {
                return PartialView("_ErrorModalPartial", "Không tìm thấy thực đơn hoặc bạn không có quyền chỉnh sửa.");
            }
            return PartialView("_MenuFormPartial", viewModel);
        }

        // POST: /Business/CreateMenu
        [HttpPost]
        [ValidateAntiForgeryToken] // Quan trọng khi form được submit bằng cách truyền thống hoặc AJAX post data
        public async Task<IActionResult> CreateMenu(MenuEditViewModel model) // [FromBody] để nhận JSON từ AJAX
        {
            // Kiểm tra lại ModelState một lần nữa ở server-side,
            // mặc dù jquery-ajax-unobtrusive cũng có thể gửi các lỗi validation từ client.
            if (!ModelState.IsValid)
            {
                // Trả về lỗi dưới dạng JSON để JavaScript có thể xử lý
                var errors = ModelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );
                Response.StatusCode = 400;
                return Json(new { success = false, errors = errors, message = "Dữ liệu không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng. Vui lòng đăng nhập lại." });
            }

            // Gọi service để tạo menu
            var result = await _menuService.CreateMenuAsync(model, ownerId);

            if (result.Success)
            {
                // Trả về success và có thể cả ID của menu mới tạo nếu JS cần để cập nhật UI
                // var createdMenu = await _menuService.GetMenuForEditAsync(result.Id, ownerId); // Lấy lại thông tin nếu cần
                return Json(new { success = true, message = $"Thực đơn '{model.Title}' đã được tạo thành công." /*, newMenuId = result.Id */ });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể tạo thực đơn. Vui lòng thử lại." });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditMenu(MenuEditViewModel model)
        {
            if (model.Id == 0) // ID của menu phải có khi sửa
            {
                return Json(new { success = false, message = "ID thực đơn không hợp lệ." });
            }

            if (!ModelState.IsValid)
            {
                var errors = ModelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );
                return Json(new { success = false, errors = errors, message = "Dữ liệu không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng. Vui lòng đăng nhập lại." });
            }

            var result = await _menuService.UpdateMenuAsync(model, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = $"Thực đơn '{model.Title}' đã được cập nhật thành công." });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể cập nhật thực đơn. Vui lòng thử lại." });
            }
        }

        [HttpPost] // Sử dụng POST cho thao tác xóa để dễ dàng gửi AntiForgeryToken
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteMenu(int id) // Nhận ID trực tiếp
        {
            if (id <= 0)
            {
                return Json(new { success = false, message = "ID thực đơn không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng. Vui lòng đăng nhập lại." });
            }

            var result = await _menuService.DeleteMenuAsync(id, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = "Thực đơn đã được xóa thành công." });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể xóa thực đơn. Vui lòng thử lại." });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetMenuStructurePartial(int restaurantId)
        {
            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return PartialView("_ErrorModalPartial", "Phiên làm việc hết hạn hoặc lỗi xác thực.");
            }

            var viewModel = await _menuService.GetRestaurantMenuForManagementAsync(restaurantId, ownerId);
            if (viewModel == null)
            {
                // Service đã log, không cần log lại ở đây
                return PartialView("_ErrorModalPartial", "Không thể tải cấu trúc thực đơn. Nhà hàng không tồn tại hoặc bạn không có quyền.");
            }
            ViewBag.RestaurantId = restaurantId; // Truyền RestaurantId cho các nút "Thêm Mục", "Thêm Món" trong partial
            return PartialView("_MenuStructurePartial", viewModel.Menus);
        }

        [HttpGet]
        public async Task<IActionResult> GetCreateMenuSectionForm(int menuId, int restaurantId) // Giữ restaurantId để ViewModel có
        {
            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId)) return Unauthorized();

            // Gọi service để lấy thông tin menu và kiểm tra quyền
            var menuInfoResult = await _menuService.GetMenuInfoForSectionCreationAsync(menuId, ownerId);

            if (!menuInfoResult.IsValidOwner)
            {
                _logger.LogWarning("User {OwnerId} attempted to access GetCreateMenuSectionForm for menu ID {MenuId} they do not own or does not exist.", ownerId, menuId);
                return PartialView("_ErrorModalPartial", "Thực đơn không hợp lệ hoặc bạn không có quyền tạo mục cho thực đơn này.");
            }

            // Đảm bảo restaurantId từ route (nếu vẫn truyền) khớp với restaurantId của menu
            if (menuInfoResult.RestaurantId != restaurantId)
            {
                _logger.LogWarning("Mismatched restaurantId in GetCreateMenuSectionForm. Route: {RouteRestaurantId}, Menu's Restaurant: {MenuRestaurantId}", restaurantId, menuInfoResult.RestaurantId);
                return PartialView("_ErrorModalPartial", "Thông tin không nhất quán. Vui lòng thử lại.");
            }

            var viewModel = new MenuSectionEditViewModel
            {
                MenuId = menuId,
                MenuName = menuInfoResult.MenuName,
                RestaurantId = menuInfoResult.RestaurantId, // Lấy RestaurantId từ kết quả service
            };

            viewModel.DisplayOrder = await _menuService.GetNextMenuSectionDisplayOrderAsync(menuId, ownerId); // ownerId để kiểm tra quyền

            return PartialView("_MenuSectionFormPartial", viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> GetEditMenuSectionForm(int sectionId)
        {
            var ownerId = _userManager.GetUserId(User);
            var viewModel = await _menuService.GetMenuSectionForEditAsync(sectionId, ownerId);

            if (viewModel == null)
            {
                return PartialView("_ErrorModalPartial", "Không tìm thấy mục thực đơn hoặc bạn không có quyền chỉnh sửa.");
            }
            return PartialView("_MenuSectionFormPartial", viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateMenuSection(MenuSectionEditViewModel model)
        {
            if (!ModelState.IsValid)
            {
                // Logic trả về lỗi ModelState dưới dạng JSON như đã làm cho CreateMenu
                var errors = ModelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );
                return Json(new { success = false, errors = errors, message = "Dữ liệu không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng. Vui lòng đăng nhập lại." });
            }

            // Service sẽ kiểm tra quyền dựa trên model.MenuId và model.RestaurantId
            var result = await _menuService.CreateMenuSectionAsync(model, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = $"Mục '{model.Title}' đã được tạo thành công." /*, newSectionId = result.Id (nếu service trả về) */ });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể tạo mục thực đơn." });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditMenuSection(MenuSectionEditViewModel model)
        {
            if (model.Id == 0)
            {
                return Json(new { success = false, message = "ID mục thực đơn không hợp lệ để chỉnh sửa." });
            }

            if (!ModelState.IsValid)
            {
                var errors = ModelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );
                return Json(new { success = false, errors = errors, message = "Dữ liệu không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng." });
            }

            var result = await _menuService.UpdateMenuSectionAsync(model, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = $"Mục '{model.Title}' đã được cập nhật." });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể cập nhật mục thực đơn." });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // Giữ lại cho form submit kiểu application/x-www-form-urlencoded (mặc định của $.ajax nếu không set contentType cho data là JSON)
        public async Task<IActionResult> DeleteMenuSection(int id) // Nhận ID từ data của AJAX
        {
            if (id <= 0)
            {
                return Json(new { success = false, message = "ID mục thực đơn không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng." });
            }

            var result = await _menuService.DeleteMenuSectionAsync(id, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = "Mục thực đơn đã được xóa thành công." });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể xóa mục thực đơn." });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetCreateMenuItemForm(int sectionId, int restaurantId)
        {
            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId)) return Unauthorized("Vui lòng đăng nhập để thực hiện chức năng này.");

            // Gọi service để chuẩn bị ViewModel, service sẽ kiểm tra quyền
            var viewModel = await _menuService.GetMenuItemForEditAsync(0, ownerId, sectionId, restaurantId);

            if (viewModel == null)
            {
                // Service đã log, hoặc bạn có thể trả về lỗi cụ thể hơn nếu service trả về enum/object lỗi
                return PartialView("_ErrorModalPartial", "Không thể tạo món ăn cho mục này hoặc bạn không có quyền.");
            }
            return PartialView("_MenuItemFormPartial", viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> GetEditMenuItemForm(int itemId)
        {
            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId)) return Unauthorized("Vui lòng đăng nhập để thực hiện chức năng này.");

            var viewModel = await _menuService.GetMenuItemForEditAsync(itemId, ownerId);

            if (viewModel == null)
            {
                return PartialView("_ErrorModalPartial", "Không tìm thấy món ăn hoặc bạn không có quyền chỉnh sửa.");
            }
            return PartialView("_MenuItemFormPartial", viewModel);
        }

        [HttpPost]
        public async Task<IActionResult> CreateMenuItem([FromForm] MenuItemEditViewModel model)
        {
            // Xóa lỗi ModelState của AvailableCategories vì nó không được gửi từ client và không cần validate ở đây
            ModelState.Remove(nameof(model.AvailableCategories));

            if (!ModelState.IsValid)
            {
                var errors = ModelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );
                // Nếu lỗi, client side (JavaScript) sẽ xử lý hiển thị lỗi từ JSON này
                // hoặc nếu không có AJAX, bạn cần populate lại AvailableCategories và trả về PartialView
                return Json(new { success = false, errors = errors, message = "Dữ liệu không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng. Vui lòng đăng nhập lại." });
            }

            var result = await _menuService.CreateMenuItemAsync(model, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = $"Món ăn '{model.Name}' đã được tạo thành công." });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể tạo món ăn. Vui lòng thử lại." });
            }
        }

        [HttpPost]
        public async Task<IActionResult> EditMenuItem([FromForm] MenuItemEditViewModel model)
        {
            if (model.Id == 0)
            {
                return Json(new { success = false, message = "ID món ăn không hợp lệ để chỉnh sửa." });
            }

            ModelState.Remove(nameof(model.AvailableCategories));
            ModelState.Remove(nameof(model.NewMainImageFile));

            if (!ModelState.IsValid)
            {
                var errors = ModelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );
                return Json(new { success = false, errors = errors, message = "Dữ liệu không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng." });
            }

            var result = await _menuService.UpdateMenuItemAsync(model, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = $"Món ăn '{model.Name}' đã được cập nhật thành công." });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể cập nhật món ăn." });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // Giữ lại vì $.ajax gửi data kiểu form-urlencoded
        public async Task<IActionResult> DeleteMenuItem(int id)
        {
            if (id <= 0)
            {
                return Json(new { success = false, message = "ID món ăn không hợp lệ." });
            }

            var ownerId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(ownerId))
            {
                return Json(new { success = false, message = "Không thể xác định người dùng." });
            }

            var result = await _menuService.DeleteMenuItemAsync(id, ownerId);

            if (result.Success)
            {
                return Json(new { success = true, message = "Món ăn đã được xóa thành công." });
            }
            else
            {
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể xóa món ăn." });
            }
        }

        // Helper method để populate AvailableCuisineTypes và AvailableTags
        private async Task PopulateAvailableOptionsAsync(RegisterRestaurantViewModel model)
        {
            var allCuisines = await _cuisineTypeService.GetAllAsync();
            model.AvailableCuisineTypes = allCuisines.Select(c => new SelectableCuisineTypeViewModel
            {
                Id = c.Id,
                Name = c.Name,
                IconUrl = c.IconUrl,
                // Giữ lại trạng thái selected nếu model.SelectedCuisineTypeIds đã có giá trị (từ lần submit lỗi trước)
                IsSelected = model.SelectedCuisineTypeIds?.Contains(c.Id) ?? false
            }).ToList();

            var allTags = await _tagService.GetAllAsync();
            model.AvailableTags = allTags.Select(t => new SelectableTagViewModel
            {
                Id = t.Id,
                Name = t.Name,
                IconUrl = t.IconUrl,
                IsSelected = model.SelectedTagIds?.Contains(t.Id) ?? false
            }).ToList();
        }

        private async Task PopulateAvailableOptionsForEditAsync(EditRestaurantViewModel model)
        {
            var allCuisines = await _cuisineTypeService.GetAllAsync();
            model.AvailableCuisineTypes = allCuisines.Select(c => new SelectableCuisineTypeViewModel
            {
                Id = c.Id,
                Name = c.Name,
                IconUrl = c.IconUrl,
                // Giữ lại trạng thái selected nếu model.SelectedCuisineTypeIds đã có giá trị
                IsSelected = model.SelectedCuisineTypeIds?.Contains(c.Id) ?? false
            }).ToList();

            var allTags = await _tagService.GetAllAsync();
            model.AvailableTags = allTags.Select(t => new SelectableTagViewModel
            {
                Id = t.Id,
                Name = t.Name,
                IconUrl = t.IconUrl,
                IsSelected = model.SelectedTagIds?.Contains(t.Id) ?? false
            }).ToList();
        }
    }
}