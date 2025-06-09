using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PBL3.Models;
using PBL3.Services.Interfaces;
using PBL3.ViewModel.Review;
using System.Threading.Tasks;

namespace PBL3.Controllers
{
    public class ReviewsController : Controller
    {
        private readonly IReviewService _reviewService;
        private readonly UserManager<AppUser> _userManager;
        private readonly IRestaurantService _restaurantService;
        private readonly SignInManager<AppUser> _signInManager;

        public ReviewsController(SignInManager<AppUser> signInManager, IReviewService reviewService, UserManager<AppUser> userManager, IRestaurantService restaurantService)
        {
            _reviewService = reviewService;
            _userManager = userManager;
            _restaurantService = restaurantService;
            _signInManager = signInManager;
        }

        [HttpGet]
        public IActionResult HandleWriteReview()
        {
            if (_signInManager.IsSignedIn(User))
            {
                // Đã đăng nhập, chuyển đến trang chọn nhà hàng để review
                return RedirectToAction(nameof(SelectRestaurantForReview));
            }
            else
            {
                TempData["ShowLoginModal"] = "true"; // Truyền dưới dạng string
                TempData["LoginReturnUrl"] = Url.Action(nameof(SelectRestaurantForReview), "Reviews");

                // Luôn redirect về trang chủ (hoặc một trang đích an toàn khác)
                // Trang chủ sẽ có JavaScript để đọc TempData và mở modal.
                return RedirectToAction("Index", "Home");
            }
        }

        [Authorize] // Chỉ người đã đăng nhập mới vào được trang này
        public IActionResult SelectRestaurantForReview()
        {
            // TODO: Implement logic để hiển thị UI cho việc chọn nhà hàng
            // Ví dụ: trả về một View với ô tìm kiếm nhà hàng
            // Sau khi chọn, sẽ redirect đến /Reviews/Create?restaurantId={id}
            ViewData["Message"] = "Đây là trang để bạn chọn nhà hàng muốn đánh giá.";
            return View(); // Cần tạo View Views/Reviews/SelectRestaurantForReview.cshtml
        }

        // GET: Reviews/Create?restaurantId=5
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Create(int restaurantId)
        {
            var restaurant = await _restaurantService.GetRestaurantByIdAsync(restaurantId); // Dùng service để lấy nhà hàng
            if (restaurant == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy nhà hàng để đánh giá.";
                return RedirectToAction("Index", "Home"); // Hoặc trang tìm kiếm nhà hàng
            }

            var viewModel = new CreateReviewViewModel
            {
                RestaurantId = restaurantId,
                RestaurantName = restaurant.Name
            };
            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateReviewViewModel model)
        {
            // RestaurantName không phải là trường người dùng nhập, không cần validate ở đây
            ModelState.Remove(nameof(model.RestaurantName));
            // Photos là tùy chọn, nếu không có file nào được chọn, model.Photos có thể null hoặc rỗng
            // Nếu bạn có validation attribute cho Photos (ví dụ: giới hạn số lượng, kích thước),
            // thì cần xử lý ở đây hoặc trong service. Hiện tại, giả sử không có validation attribute đặc biệt cho nó.

            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null)
            {
                // Điều này gần như không thể xảy ra do [Authorize] trên controller
                // nhưng là một bước kiểm tra an toàn.
                return Challenge(); // Yêu cầu đăng nhập lại
            }

            if (ModelState.IsValid)
            {
                // Gọi service để tạo review
                var result = await _reviewService.CreateReviewAsync(model, currentUser.Id);

                if (result.Success)
                {
                    TempData["SuccessMessage"] = "Cảm ơn bạn đã gửi đánh giá! Đánh giá của bạn đã được ghi nhận.";
                    // Chuyển hướng về trang chi tiết nhà hàng vừa đánh giá
                    return RedirectToAction("Details", "Restaurants", new { id = model.RestaurantId });
                }
                else
                {
                    // Nếu service trả về lỗi, hiển thị lỗi đó
                    ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Không thể gửi đánh giá. Đã có lỗi xảy ra.");
                }
            }

            // Nếu ModelState không hợp lệ, hoặc service thất bại, chuẩn bị lại dữ liệu cho View
            // Lấy lại tên nhà hàng để hiển thị trên form
            if (string.IsNullOrEmpty(model.RestaurantName) && model.RestaurantId > 0)
            {
                var restaurant = await _restaurantService.GetRestaurantByIdAsync(model.RestaurantId);
                model.RestaurantName = restaurant?.Name;
            }
            // Nếu không tìm thấy restaurant hoặc RestaurantId không hợp lệ,
            // có thể thêm một lỗi chung vào ModelState
            if (string.IsNullOrEmpty(model.RestaurantName))
            {
                ModelState.AddModelError(string.Empty, "Không thể xác định nhà hàng để đánh giá. Vui lòng thử lại từ trang nhà hàng.");
            }

            return View(model); // Trả về View với model và các lỗi validation
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> MyReviews()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var userReviewsViewModel = await _reviewService.GetUserReviewsAsync(user.Id);
            ViewData["UserDisplayName"] = user.DisplayName ?? user.UserName; // Optional
            return View(userReviewsViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // Hoạt động vì $.ajax gửi data như form
        public async Task<IActionResult> DeleteReview(int id) // id được bind từ route hoặc form data
        {
            if (id <= 0)
            {
                return Json(new { success = false, message = "ID đánh giá không hợp lệ." });
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Json(new { success = false, message = "Không thể xác định người dùng." });
            }

            var result = await _reviewService.DeleteReviewAsync(id, user.Id);

            if (result.Success)
            {
                return Json(new { success = true, message = "Đánh giá của bạn đã được xóa." });
            }
            else
            {
                // Trả về lỗi để client xử lý, có thể là 400 hoặc 500 tùy theo lỗi
                // Response.StatusCode = StatusCodes.Status400BadRequest; // Ví dụ
                return Json(new { success = false, message = result.ErrorMessage ?? "Không thể xóa đánh giá." });
            }
        }

        [HttpGet]
        public async Task<IActionResult> EditReview(int? id)
        {
            if (id == null) return NotFound();

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var viewModel = await _reviewService.GetReviewForEditAsync(id.Value, user.Id);
            if (viewModel == null)
            {
                TempData["ErrorMessage"] = "Không tìm thấy đánh giá hoặc bạn không có quyền chỉnh sửa.";
                return RedirectToAction(nameof(MyReviews)); // Hoặc một trang lỗi khác
            }
            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditReview(int id, EditReviewViewModel model)
        {
            if (id != model.ReviewId) return BadRequest();

            // RestaurantName không phải là trường người dùng nhập, không cần validate ở đây
            ModelState.Remove(nameof(model.RestaurantName));
            // CurrentPhotos chỉ để hiển thị, NewPhotos là tùy chọn
            ModelState.Remove(nameof(model.CurrentPhotos));
            ModelState.Remove(nameof(model.NewPhotos));


            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            if (ModelState.IsValid)
            {
                var result = await _reviewService.UpdateReviewAsync(model, user.Id);
                if (result.Success)
                {
                    TempData["SuccessMessage"] = "Đánh giá của bạn đã được cập nhật thành công.";
                    return RedirectToAction(nameof(MyReviews)); // Hoặc về trang chi tiết nhà hàng
                }
                else
                {
                    ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Không thể cập nhật đánh giá.");
                }
            }

            // Nếu ModelState không hợp lệ hoặc service thất bại, chuẩn bị lại dữ liệu cho View
            if (string.IsNullOrEmpty(model.RestaurantName) && model.RestaurantId > 0)
            {
                var restaurant = await _restaurantService.GetRestaurantByIdAsync(model.RestaurantId); // Dùng _restaurantService
                model.RestaurantName = restaurant?.Name;
            }
            // Cần load lại CurrentPhotos nếu model không hợp lệ và trả về View
            // (GetReviewForEditAsync đã làm việc này, nhưng ở đây model đã có CurrentPhotos từ POST request)
            // Nếu NewPhotos gây lỗi, có thể cần xóa chúng khỏi model trước khi trả về View.

            return View(model);
        }

    }
}
