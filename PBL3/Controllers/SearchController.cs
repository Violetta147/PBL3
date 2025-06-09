using Microsoft.AspNetCore.Mvc;
using PBL3.Models;
using PBL3.ViewModel;
using PBL3.Services.Interfaces;
using PBL3.Data;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq; // Add this for .Select() and .FirstOrDefault()
using System.Threading.Tasks;
using System.Collections; // Add this for async operations
using X.PagedList;
using Microsoft.Extensions.Logging;

namespace PBL3.Controllers
{    public class SearchController : Controller
    {   
        private readonly IRestaurantService _restaurantService;
        private readonly IGeoLocationService _geoLocationService;
        private readonly IConfiguration _config;
        private readonly ILogger<SearchController> _logger;
        
        public SearchController(IRestaurantService restaurantService, IGeoLocationService geoLocationService, IConfiguration config, ILogger<SearchController> logger)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _restaurantService = restaurantService ?? throw new ArgumentNullException(nameof(restaurantService));
            _geoLocationService = geoLocationService ?? throw new ArgumentNullException(nameof(geoLocationService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }public async Task<IActionResult> Index(string searchTerm = "", string Address = "", int page = 1, int pageSize = 10, IEnumerable<int>? tagIds = null, IEnumerable<int>? cuisineTypeIds = null, string? sortBy = null, decimal? minPrice = null, decimal? maxPrice = null, string maxDistance = "", double? lat = null, double? lng = null)
        {
            //logging for detecting if controller is getting called
            _logger.LogInformation("SearchController Index action called with parameters: SearchTerm={SearchTerm}, Address={Address}, Page={Page}, PageSize={PageSize}, TagIds={TagIds}, CuisineTypeIds={CuisineTypeIds}, SortBy={SortBy}, MinPrice={MinPrice}, MaxPrice={MaxPrice}, MaxDistance={MaxDistance}, Lat={Lat}, Lng={Lng}", 
                searchTerm, Address, page, pageSize, tagIds, cuisineTypeIds, sortBy, minPrice, maxPrice, maxDistance, lat, lng);        
            //Mapbox token
            ViewBag.MapboxToken = _config["Mapbox:AccessToken"];
            ViewBag.CuisineTypes = await _restaurantService.GetCuisineTypesAsync();

            // Chuẩn hóa thông tin vị trí và bán kính tìm kiếm - using enhanced Vietnamese geocoding
            _logger.LogInformation("Processing search with address: {Address}, Lat: {Lat}, Lng: {Lng}", Address, lat, lng);
            var normalizedLocation = await _restaurantService.NormalizeLocationParameters(Address, lat, lng, maxDistance);
            
            var svm = new SearchViewModel
            {
                SearchTerm = searchTerm,
                Address = normalizedLocation.address,
                Page = page,
                PageSize = pageSize,
                TagIds = tagIds,
                CuisineTypeIds = cuisineTypeIds,
                SortBy = sortBy ?? "relevance", // Sử dụng "relevance" khi sortBy là null
                MinPrice = minPrice,
                MaxPrice = maxPrice,
                MaxDistance = maxDistance,
                Lat = normalizedLocation.latitude,
                Lng = normalizedLocation.longitude
            };
            
            svm.RestaurantCards = await SearchByTermAndLocationAsync(searchTerm, Address, svm.Lat, svm.Lng, normalizedLocation.radiusInKm, cuisineTypeIds, tagIds, minPrice, maxPrice, svm.SortBy, page, pageSize);
            return View(svm);
        } 
          private async Task<IPagedList<RestaurantCardViewModel>> SearchByTermAndLocationAsync(string searchTerm, string address, double? latitude, double? longitude, double? radiusInKm, IEnumerable<int>? cuisineTypeIds, IEnumerable<int>? tagIds, decimal? minPrice, decimal? maxPrice, string? sortBy, int page, int pageSize)
        {
            // Ensure sortBy is not null
            sortBy = string.IsNullOrEmpty(sortBy) ? "relevance" : sortBy;
            
            // Log sortBy value for debugging
            _logger.LogInformation($"Sorting by: {sortBy}");
            
            // Use advanced search from service
            var pagedRestaurants = await _restaurantService.SearchRestaurantsAdvancedAsync(searchTerm, address, latitude, longitude, radiusInKm, cuisineTypeIds, tagIds, minPrice, maxPrice, sortBy, page, pageSize);
            // Map results to view model
            var restaurantCards = pagedRestaurants.Select(r => new RestaurantCardViewModel
            {
                Id = r.Id,
                Name = r.Name,
                CardImageUrl = "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/27/d5/bb/74/lounge.jpg?w=900&h=500&s=1", //r.MainImageUrl ?? 
                CuisineSummary = r.RestaurantCuisines?.Select(rc => rc.CuisineType.Name).ToList<string?>() ?? new List<string?>(),
                AverageRating = r.AverageRating,
                ReviewCount = r.ReviewCount,
                FullAddress = r.Address?.FullAddress ?? "",
                OperatingHours = r.OperatingHours,
                MinTypicalPrice = r.MinTypicalPrice,
                MaxTypicalPrice = r.MaxTypicalPrice,
                Latitude = r.Address?.Latitude,
                Longitude = r.Address?.Longitude,
            }).ToList();
            
            // Return as IPagedList
            return new StaticPagedList<RestaurantCardViewModel>(
            restaurantCards,
            pagedRestaurants.PageNumber,
            pagedRestaurants.PageSize,
            pagedRestaurants.TotalItemCount
            );
        } 
    }
}