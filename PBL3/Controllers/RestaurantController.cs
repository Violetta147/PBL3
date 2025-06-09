using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc;
using PBL3.Services.Interfaces;
using System.Threading.Tasks;
using PBL3.ViewModel;

namespace PBL3.Controllers
{
    public class RestaurantsController : Controller
    {
        private readonly IRestaurantService _restaurantService;
        private readonly ILogger<RestaurantsController> _logger;

        public RestaurantsController(IRestaurantService restaurantService, ILogger<RestaurantsController> logger)
        {
            _restaurantService = restaurantService;
            _logger = logger;
        }

        // GET: Restaurants/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound(); // Hoặc BadRequest()
            }

            var viewModel = await _restaurantService.GetRestaurantDetailViewModelAsync(id.Value);

            if (viewModel == null)
            {
                _logger.LogWarning("Restaurant with ID {RestaurantId} not found or not accessible.", id.Value);
                return NotFound(); // Hiển thị trang 404
            }

            return View(viewModel);
        }

        // ... (Action Search/Index sẽ được làm sau)
    }
}
