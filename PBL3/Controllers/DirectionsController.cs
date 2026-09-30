using Microsoft.AspNetCore.Mvc;
using PBL3.ViewModel;
using PBL3.Services.Interfaces;

namespace PBL3.Controllers
{
    public class DirectionsController : Controller
    {   
        private readonly IRestaurantService _restaurantService;
        private readonly IConfiguration _config;
        public DirectionsController(IRestaurantService restaurantService, IConfiguration config)
        {
            _restaurantService = restaurantService;
            _config = config;
        }
        public async Task<IActionResult> Index(double lat, double lon, int? locationId)
        {
            // Kiểm tra tham số hợp lệ
            if (lat < -90 || lat > 90 || lon < -180 || lon > 180)
            {
                TempData["Error"] = "Tọa độ không hợp lệ";
                return RedirectToAction("Index", "Home");
            }

            //mapbox token
            ViewBag.MapboxToken = _config["Mapbox:AccessToken"];
            var model = new DirectionsViewModel
            {
                Latitude = lat,
                Longitude = lon,
                LocationId = locationId
            };

            // Nếu có locationId, có thể lấy thêm thông tin từ database
            if (locationId.HasValue)
            {
                // Ví dụ lấy thông tin location từ database
                var restaurant = await _restaurantService.GetRestaurantByIdAsync(locationId.Value);
                // Tạm thời hardcode để test
                model.LocationName = restaurant?.Name ?? "N/A";
                model.LocationAddress = restaurant?.Address?.FullAddress ?? "N/A";
            }

            return View(model);
        }
    }
}