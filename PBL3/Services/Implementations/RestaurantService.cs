using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using PBL3.Data;
using PBL3.Extensions;
using PBL3.Models;
using PBL3.Models.Common; // Nếu PagedResult, RestaurantCreationResult ở đây
using PBL3.Services.Interfaces;
using PBL3.ViewModel.Restaurant;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using X.PagedList.EF;
using PBL3.ViewModel.Menu;
using PBL3.ViewModel.Restaurant;
using PBL3.ViewModel.Admin;
using X.PagedList;
namespace PBL3.Services.Implementations
{
    public class RestaurantService : IRestaurantService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<AppUser> _userManager; // Có thể cần cho một số logic owner
        private readonly IPhotoService _photoService;    // Để xử lý upload ảnh
        private readonly ILogger<RestaurantService> _logger;
        private readonly IGeoLocationService? _geoLocationService;

        public RestaurantService(ApplicationDbContext context, UserManager<AppUser> userManager, IPhotoService photoService, ILogger<RestaurantService> logger, IGeoLocationService? geoLocationService = null)
        {
            _context = context;
            _userManager = userManager;
            _photoService = photoService;
            _geoLocationService = geoLocationService;
            _logger = logger;
        }
        public async Task<IEnumerable<CuisineType>> GetCuisineTypesAsync()
        {
            return await _context.CuisineTypes
                                 .OrderBy(ct => ct.Name) // Sắp xếp theo tên cho dễ nhìn
                                 .ToListAsync();
        }
        public async Task<IEnumerable<Tag>> GetTagsAsync()
        {
            return await _context.Tags
                       .OrderBy(t => t.Name) // Sắp xếp theo tên
                       .ToListAsync();
        }
        public async Task<IEnumerable<MyRestaurantListItemViewModel>> GetRestaurantsByOwnerIdAsync(string ownerId)
        {
            var restaurants = await _context.Restaurants
                .Where(r => r.OwnerId == ownerId && r.Status != RestaurantStatus.ClosedPermanently) // Lấy cả những quán tạm đóng
                .Include(r => r.Address) // Cần Address để hiển thị
                                         // .Include(r => r.Reviews) // Chỉ Include nếu bạn cần tính toán lại AverageRating/ReviewCount ở đây.
                                         // Nếu chúng đã được cập nhật trong bảng Restaurant thì không cần.
                .OrderByDescending(r => r.UpdatedAt) // Sắp xếp theo lần cập nhật mới nhất hoặc ngày tạo
                .ToListAsync();

            // var urlHelper = _urlHelperFactory.GetUrlHelper(_actionContextAccessor.ActionContext); // Nếu muốn tạo URL tuyệt đối

            return restaurants.Select(r => new MyRestaurantListItemViewModel
            {
                Id = r.Id,
                Name = r.Name,
                MainImageUrl = r.MainImageUrl,
                FullAddressText = r.Address != null ?
                    $"{r.Address.AddressLine1}, {r.Address.Ward}, {r.Address.District}, {r.Address.City}"
                    : "Chưa cập nhật địa chỉ",
                Status = r.Status, // StatusDisplayName sẽ được xử lý bởi getter trong ViewModel
                CreatedAt = r.CreatedAt,
                ReviewCount = r.ReviewCount, // Lấy từ trường đã được cập nhật trong Restaurant
                AverageRating = r.AverageRating, // Lấy từ trường đã được cập nhật trong Restaurant

                // Tạo URL tương đối. Controller hoặc View sẽ xử lý việc tạo URL đầy đủ nếu cần.
                // Hoặc bạn có thể hardcode như cũ nếu routing đơn giản.
                ViewDetailsUrl = $"/Restaurants/Details/{r.Id}",
                EditRestaurantUrl = $"/Business/EditRestaurant/{r.Id}", // Giả sử có action này
                ManageMenuUrl = $"/Business/ManageMenu/{r.Id}"       // Giả sử có action này
                                                                     // ManagePromotionsUrl = $"/Business/ManagePromotions/{r.Id}"
            }).ToList();
        }
        public async Task<Restaurant?> GetRestaurantByIdAsync(int id)
        {
            // Query này đã rất tốt, bao gồm nhiều Include cần thiết
            return await _context.Restaurants
                .Include(r => r.Address)
                .Include(r => r.OperatingHours)
                .Include(r => r.Photos) // RestaurantPhoto
                .Include(r => r.RestaurantCuisines).ThenInclude(rc => rc.CuisineType)
                .Include(r => r.RestaurantTags).ThenInclude(rt => rt.Tag)
                .Include(r => r.Menus)
                    .ThenInclude(m => m.MenuSections)
                        .ThenInclude(ms => ms.MenuItems)
                            .ThenInclude(mi => mi.Photos) // MenuItemPhoto
                .Include(r => r.Menus)
                    .ThenInclude(m => m.MenuSections)
                        .ThenInclude(ms => ms.MenuItems)
                            .ThenInclude(mi => mi.MenuItemCategories)
                                .ThenInclude(mc => mc.Category)
                .Include(r => r.Reviews)
                    .ThenInclude(rev => rev.User) // Lấy thông tin người review
                .Include(r => r.Reviews)
                    .ThenInclude(rev => rev.Photos) // ReviewPhoto
                .Include(r => r.Owner)
                .AsNoTracking() // Thêm AsNoTracking vì đây là query chỉ để đọc, giúp tăng hiệu suất
                .FirstOrDefaultAsync(r => r.Id == id && r.Status != RestaurantStatus.ClosedPermanently);
        }
        public async Task<PagedResult<RestaurantListItemViewModel>> SearchRestaurantsAsync(
                    string? searchTerm = null,
                    IEnumerable<int>? cuisineTypeIds = null,
                    IEnumerable<int>? tagIds = null,
                    decimal? minUserPrice = null, // Đổi tên để rõ ràng là giá người dùng tìm kiếm
                    decimal? maxUserPrice = null, // Đổi tên
                    bool? isOpenNow = null,
                    string? sortBy = null,
                    int pageNumber = 1,
                    int pageSize = 10)
        {
            var query = _context.Restaurants
                                .Where(r => r.Status == RestaurantStatus.Open) // Chỉ lấy nhà hàng đang hoạt động
                                .AsQueryable();

            // 1. Lọc theo searchTerm
            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                var term = searchTerm.ToLower().Trim();
                query = query.Where(r => EF.Functions.Like(r.Name.ToLower(), $"%{term}%") ||
                                         (r.Description != null && EF.Functions.Like(r.Description.ToLower(), $"%{term}%")) ||
                                         // Tìm kiếm trong tên món ăn (cần Include và có thể ảnh hưởng hiệu suất)
                                         (r.MenuItems.Any(mi => mi.IsAvailable && EF.Functions.Like(mi.Name.ToLower(), $"%{term}%")))
                                    );
            }

            // 2. Lọc theo CuisineTypeIds
            if (cuisineTypeIds != null && cuisineTypeIds.Any())
            {
                // Nhà hàng phải có ÍT NHẤT MỘT CuisineType trong danh sách được chọn (OR logic)
                query = query.Where(r => r.RestaurantCuisines.Any(rc => cuisineTypeIds.Contains(rc.CuisineTypeId)));
                // Nếu muốn logic AND (phải có tất cả):
                // foreach (var cuisineId in cuisineTypeIds)
                // {
                //     query = query.Where(r => r.RestaurantCuisines.Any(rc => rc.CuisineTypeId == cuisineId));
                // }
            }

            // 3. Lọc theo TagIds
            if (tagIds != null && tagIds.Any())
            {
                // Tương tự, OR logic:
                query = query.Where(r => r.RestaurantTags.Any(rt => tagIds.Contains(rt.TagId)));
                // Nếu muốn logic AND:
                // foreach (var tagId in tagIds)
                // {
                //     query = query.Where(r => r.RestaurantTags.Any(rt => rt.TagId == tagId));
                // }
            }

            // 4. Lọc theo khoảng giá (MinTypicalPrice, MaxTypicalPrice của nhà hàng)
            // Tìm nhà hàng có khoảng giá GIAO THOA với khoảng người dùng tìm kiếm [minUserPrice, maxUserPrice]
            if (minUserPrice.HasValue && maxUserPrice.HasValue)
            {
                query = query.Where(r => r.MinTypicalPrice.HasValue && r.MaxTypicalPrice.HasValue &&
                                         r.MinTypicalPrice <= maxUserPrice.Value && r.MaxTypicalPrice >= minUserPrice.Value);
            }
            else if (minUserPrice.HasValue)
            {
                query = query.Where(r => r.MaxTypicalPrice.HasValue && r.MaxTypicalPrice >= minUserPrice.Value);
            }
            else if (maxUserPrice.HasValue)
            {
                query = query.Where(r => r.MinTypicalPrice.HasValue && r.MinTypicalPrice <= maxUserPrice.Value);
            }

            // 6. Sắp xếp (đặt trước khi phân trang và trước khi lọc IsOpenNow nếu lọc ở client)
            string normalizedSortBy = sortBy?.ToLower().Trim() ?? "rating_desc"; // Mặc định theo rating
            switch (normalizedSortBy)
            {
                case "rating_desc":
                    query = query.OrderByDescending(r => r.AverageRating).ThenByDescending(r => r.ReviewCount);
                    break;
                case "name_asc":
                    query = query.OrderBy(r => r.Name);
                    break;
                case "price_asc":
                    query = query.OrderBy(r => r.MinTypicalPrice ?? decimal.MaxValue);
                    break;
                case "price_desc":
                    query = query.OrderByDescending(r => r.MaxTypicalPrice ?? decimal.MinValue);
                    break;
                case "newest_desc":
                    query = query.OrderByDescending(r => r.CreatedAt);
                    break;
                default:
                    query = query.OrderByDescending(r => r.AverageRating).ThenByDescending(r => r.ReviewCount);
                    break;
            }

            // Lấy tất cả các nhà hàng phù hợp với các bộ lọc trên (chưa phân trang)
            // Chúng ta sẽ lọc isOpenNow ở phía client sau khi lấy về để đơn giản hóa query DB ban đầu
            // Điều này có thể không tối ưu nếu tập kết quả lớn trước khi lọc isOpenNow.
            var allMatchingRestaurants = await query
                .Include(r => r.Address)
                .Include(r => r.OperatingHours) // Cần cho IsOpenNow
                .Include(r => r.RestaurantCuisines).ThenInclude(rc => rc.CuisineType)
                .Include(r => r.RestaurantTags).ThenInclude(rt => rt.Tag)
                .ToListAsync();

            // 5. Lọc theo IsOpenNow (lọc ở client/service side)
            IEnumerable<Restaurant> finalFilteredRestaurants = allMatchingRestaurants;
            if (isOpenNow.HasValue && isOpenNow.Value)
            {
                var currentTimeUserLocal = DateTime.Now; // Hoặc lấy múi giờ của người dùng nếu có
                                                         // Cần đảm bảo so sánh đúng múi giờ với OperatingHours
                finalFilteredRestaurants = allMatchingRestaurants
                                            .Where(r => IsRestaurantCurrentlyOpen(r, currentTimeUserLocal))
                                            .ToList();
            }

            // 7. Phân trang trên danh sách đã lọc cuối cùng
            var totalCount = finalFilteredRestaurants.Count();
            var pagedRestaurants = finalFilteredRestaurants
                                        .Skip((pageNumber - 1) * pageSize)
                                        .Take(pageSize)
                                        .ToList();

            // 8. Ánh xạ sang ViewModel
            var viewModels = pagedRestaurants.Select(r => new RestaurantListItemViewModel
            {
                Id = r.Id,
                Name = r.Name,
                MainImageUrl = r.MainImageUrl,
                AverageRating = r.AverageRating,
                ReviewCount = r.ReviewCount,
                CuisineTypeNames = r.RestaurantCuisines?.Select(rc => rc.CuisineType.Name).ToList() ?? new List<string>(),
                TagNames = r.RestaurantTags?.Select(rt => rt.Tag.Name).ToList() ?? new List<string>(),
                PriceRangeText = GetPriceRangeText(r.MinTypicalPrice, r.MaxTypicalPrice),
                ShortAddress = r.Address != null ? $"{r.Address.District}, {r.Address.City}" : "Chưa cập nhật",
                IsCurrentlyOpen = IsRestaurantCurrentlyOpen(r, DateTime.Now), // Tính lại cho ViewModel
                CurrentOpeningStatusText = GetCurrentOpeningStatusText(r, DateTime.Now) // Tính lại cho ViewModel
            }).ToList();

            return new PagedResult<RestaurantListItemViewModel>
            {
                Items = viewModels,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalCount = totalCount // totalCount này là SAU khi lọc isOpenNow
            };
        }
        // --- Helper methods
        private List<OperatingHourViewModel> GroupAndFormatOperatingHours(ICollection<OperatingHour>? operatingHours)
        {
            if (operatingHours == null || !operatingHours.Any())
            {
                return new List<OperatingHourViewModel>();
            }

            var grouped = operatingHours
                .GroupBy(oh => oh.DayOfWeek)
                .OrderBy(g => g.Key) // Sắp xếp theo ngày trong tuần
                .Select(g => new OperatingHourViewModel
                {
                    DayDisplayName = g.Key.ToVietnameseDayOfWeek(), // Cần extension method này
                    TimeSlots = g.OrderBy(oh => oh.OpenTime) // Sắp xếp các khung giờ trong ngày
                                   .Select(oh => $"{oh.OpenTime:hh\\:mm} - {oh.CloseTime:hh\\:mm}" + (!string.IsNullOrWhiteSpace(oh.Notes) ? $" ({oh.Notes})" : ""))
                                   .ToList(),
                    IsOpenToday = g.Any(), // Nếu có bất kỳ khung giờ nào cho ngày này thì coi là có mở
                    Notes = string.Join("; ", g.Select(oh => oh.Notes).Where(n => !string.IsNullOrWhiteSpace(n)).Distinct()) // Gộp các ghi chú nếu có
                })
                .ToList();

            // Đảm bảo có đủ 7 ngày, kể cả ngày không có giờ hoạt động
            var result = new List<OperatingHourViewModel>();
            for (int i = 0; i < 7; i++)
            {
                var day = (DayOfWeek)i;
                var existingDay = grouped.FirstOrDefault(g => g.DayDisplayName == day.ToVietnameseDayOfWeek());
                if (existingDay != null)
                {
                    result.Add(existingDay);
                }
                else
                {
                    result.Add(new OperatingHourViewModel { DayDisplayName = day.ToVietnameseDayOfWeek(), TimeSlots = new List<string> { "Đóng cửa" }, IsOpenToday = false });
                }
            }
            return result;
        }
        private string GetPriceRangeText(decimal? minPrice, decimal? maxPrice)
        {
            if (!minPrice.HasValue && !maxPrice.HasValue) return "Chưa cập nhật";
            if (minPrice.HasValue && !maxPrice.HasValue) return $"Từ {minPrice:N0} VNĐ";
            if (!minPrice.HasValue && maxPrice.HasValue) return $"Đến {maxPrice:N0} VNĐ";
            if (minPrice == maxPrice) return $"{minPrice:N0} VNĐ";
            return $"{minPrice:N0} - {maxPrice:N0} VNĐ";
        }
        private bool IsRestaurantCurrentlyOpen(Restaurant restaurant, DateTime currentLocalTime)
        {
            if (restaurant.Status != RestaurantStatus.Open || restaurant.OperatingHours == null || !restaurant.OperatingHours.Any())
            {
                return false;
            }

            var currentDayOfWeek = currentLocalTime.DayOfWeek;
            var currentTimeOfDay = currentLocalTime.TimeOfDay;

            // Kiểm tra các khung giờ của ngày hiện tại
            foreach (var oh in restaurant.OperatingHours.Where(h => h.DayOfWeek == currentDayOfWeek))
            {
                // Trường hợp mở qua đêm (CloseTime < OpenTime, ví dụ mở 22:00 - 02:00 sáng hôm sau)
                if (oh.CloseTime < oh.OpenTime)
                {
                    // Nếu đang là trước nửa đêm (currentTimeOfDay >= OpenTime)
                    // HOẶC đang là sau nửa đêm và trước giờ đóng cửa (currentTimeOfDay < CloseTime)
                    if (currentTimeOfDay >= oh.OpenTime || currentTimeOfDay < oh.CloseTime)
                    {
                        return true;
                    }
                }
                // Trường hợp mở và đóng trong cùng một ngày
                else if (currentTimeOfDay >= oh.OpenTime && currentTimeOfDay < oh.CloseTime)
                {
                    return true;
                }
            }

            // Kiểm tra xem có mở cửa từ ngày hôm trước qua đêm đến hôm nay không
            var yesterday = currentLocalTime.AddDays(-1).DayOfWeek;
            foreach (var ohYesterday in restaurant.OperatingHours.Where(h => h.DayOfWeek == yesterday && h.CloseTime < h.OpenTime))
            {
                // Nếu hôm qua mở qua đêm và giờ hiện tại nhỏ hơn giờ đóng cửa của ngày hôm qua
                if (currentTimeOfDay < ohYesterday.CloseTime)
                {
                    return true;
                }
            }

            return false;
        }
        private string GetCurrentOpeningStatusText(Restaurant restaurant, DateTime currentLocalTime)
        {
            if (restaurant.Status == RestaurantStatus.ClosedPermanently) return "Đóng cửa vĩnh viễn";
            if (restaurant.Status == RestaurantStatus.TemporarilyClosed) return "Tạm đóng cửa";

            if (IsRestaurantCurrentlyOpen(restaurant, currentLocalTime))
            {
                // Tìm giờ đóng cửa tiếp theo trong ngày hiện tại
                var nextClosingTimeToday = restaurant.OperatingHours
                    .Where(oh => oh.DayOfWeek == currentLocalTime.DayOfWeek &&
                                 ((oh.CloseTime >= oh.OpenTime && oh.CloseTime > currentLocalTime.TimeOfDay && currentLocalTime.TimeOfDay >= oh.OpenTime) || // Đóng trong ngày và đang mở
                                   (oh.CloseTime < oh.OpenTime && (currentLocalTime.TimeOfDay >= oh.OpenTime || currentLocalTime.TimeOfDay < oh.CloseTime)) // Mở qua đêm và đang trong giờ mở
                                 ))
                    .Select(oh => oh.CloseTime)
                    .OrderBy(ct => ct < currentLocalTime.TimeOfDay ? ct.Add(TimeSpan.FromDays(1)) : ct) // Xử lý trường hợp close time đã qua trong ngày
                    .FirstOrDefault();

                if (nextClosingTimeToday != default(TimeSpan))
                {
                    return $"Đang mở cửa - Đóng lúc {nextClosingTimeToday:hh\\:mm}";
                }

                // Nếu không tìm thấy giờ đóng cửa hôm nay (ví dụ mở 24/24 cho ngày này, hoặc mở qua đêm mà đã qua giờ đóng của khung đó)
                // thì tìm giờ đóng của khung qua đêm từ ngày hôm trước (nếu đang trong khung đó)
                var yesterday = currentLocalTime.AddDays(-1).DayOfWeek;
                var overnightClosing = restaurant.OperatingHours
                    .Where(h => h.DayOfWeek == yesterday && h.CloseTime < h.OpenTime && currentLocalTime.TimeOfDay < h.CloseTime)
                    .Select(h => h.CloseTime)
                    .FirstOrDefault();

                if (overnightClosing != default(TimeSpan))
                {
                    return $"Đang mở cửa - Đóng lúc {overnightClosing:hh\\:mm}";
                }

                return "Đang mở cửa";
            }
            else
            {
                // Tìm giờ mở cửa tiếp theo (logic này có thể phức tạp)
                // Tạm thời đơn giản:
                var todayUpcomingOpening = restaurant.OperatingHours
                    .Where(oh => oh.DayOfWeek == currentLocalTime.DayOfWeek && oh.OpenTime > currentLocalTime.TimeOfDay)
                    .OrderBy(oh => oh.OpenTime)
                    .Select(oh => oh.OpenTime)
                    .FirstOrDefault();

                if (todayUpcomingOpening != default(TimeSpan))
                {
                    return $"Đóng cửa - Mở lúc {todayUpcomingOpening:hh\\:mm} hôm nay";
                }

                // Tìm giờ mở cửa ngày tiếp theo (trong vòng 7 ngày tới)
                for (int i = 1; i <= 7; i++)
                {
                    var nextDay = currentLocalTime.AddDays(i).DayOfWeek;
                    var nextDayOpening = restaurant.OperatingHours
                        .Where(oh => oh.DayOfWeek == nextDay)
                        .OrderBy(oh => oh.OpenTime)
                        .Select(oh => oh.OpenTime)
                        .FirstOrDefault();

                    if (nextDayOpening != default(TimeSpan))
                    {
                        string dayName = i == 1 ? "ngày mai" : $"Thứ {(int)nextDay + 2}"; // Điều chỉnh cho phù hợp
                        if (nextDay == DayOfWeek.Sunday && dayName.EndsWith("8")) dayName = "Chủ Nhật";
                        else if (nextDay == DayOfWeek.Monday && dayName.EndsWith("2")) dayName = "Thứ Hai";
                        // ... thêm cho các thứ khác
                        return $"Đóng cửa - Mở lúc {nextDayOpening:hh\\:mm} {dayName}";
                    }
                }
                return "Hiện đang đóng cửa";
            }
        }

        public async Task<RestaurantDetailViewModel?> GetRestaurantDetailViewModelAsync(int id)
        {
            var restaurant = await GetRestaurantByIdAsync(id); // Gọi lại phương thức trên để lấy entity
            if (restaurant == null)
            {
                return null;
            }

            // Ánh xạ từ Restaurant entity sang RestaurantDetailViewModel
            var viewModel = new RestaurantDetailViewModel
            {
                Id = restaurant.Id,
                Name = restaurant.Name,
                Description = restaurant.Description,
                MainImageUrl = restaurant.MainImageUrl,
                OtherImageUrls = restaurant.Photos?.Select(p => p.Url).ToList() ?? new List<string>(),

                AddressLine1 = restaurant.Address?.AddressLine1 ?? string.Empty,
                Ward = restaurant.Address?.Ward ?? string.Empty,
                District = restaurant.Address?.District ?? string.Empty,
                City = restaurant.Address?.City ?? string.Empty,
                Country = restaurant.Address?.Country ?? string.Empty,
                FullAddressText = restaurant.Address?.FullAddress ?? "Chưa cập nhật địa chỉ", // Giả sử Address có FullAddress
                Latitude = restaurant.Address?.Latitude,
                Longitude = restaurant.Address?.Longitude,

                PhoneNumber = restaurant.PhoneNumber,
                Website = restaurant.Website,

                IsCurrentlyOpen = IsRestaurantCurrentlyOpen(restaurant, DateTime.Now), // Dùng helper đã có
                CurrentOverallOpeningStatusText = GetCurrentOpeningStatusText(restaurant, DateTime.Now), // Dùng helper đã có
                PriceRangeText = GetPriceRangeText(restaurant.MinTypicalPrice, restaurant.MaxTypicalPrice), // Dùng helper

                AverageRating = restaurant.AverageRating,
                ReviewCount = restaurant.ReviewCount,

                CuisineTypeNames = restaurant.RestaurantCuisines?.Select(rc => rc.CuisineType.Name).ToList() ?? new List<string>(),
                TagNames = restaurant.RestaurantTags?.Select(rt => rt.Tag.Name).ToList() ?? new List<string>(),

                OwnerDisplayName = restaurant.Owner?.DisplayName,
                OwnerAvatarUrl = restaurant.Owner?.AvatarUrl,

                // Xử lý OperatingHours
                OperatingHoursGroupedByDay = GroupAndFormatOperatingHours(restaurant.OperatingHours),

                // Xử lý Menus
                Menus = restaurant.Menus?.Select(menuEntity => new MenuViewModel
                {
                    Id = menuEntity.Id,
                    Title = menuEntity.Title,
                    Description = menuEntity.Description,
                    MenuSections = menuEntity.MenuSections?.Select(sectionEntity => new MenuSectionViewModel
                    {
                        Id = sectionEntity.Id,
                        Title = sectionEntity.Title,
                        Description = sectionEntity.Description,
                        MenuItems = sectionEntity.MenuItems?
                        .OrderBy(itemEntity => itemEntity.DisplayOrder) // <<< SẮP XẾP TRÊN ENTITY TRƯỚC
                        .Select(itemEntity => new MenuItemSummaryViewModel
                        {
                            Id = itemEntity.Id,
                            Name = itemEntity.Name,
                            Description = itemEntity.Description,
                            PriceDisplay = $"{itemEntity.Price:N0} VNĐ",
                            MainImageUrl = itemEntity.Photos?.FirstOrDefault(p => p.IsMainImage)?.Url ?? itemEntity.Photos?.FirstOrDefault()?.Url, // Lấy ảnh chính hoặc ảnh đầu tiên
                            CategoryNames = itemEntity.MenuItemCategories?.Select(mc => mc.Category.Name).ToList() ?? new List<string>(),
                            IsSignatureDish = itemEntity.IsSignatureDish,
                            DisplayOrder = itemEntity.DisplayOrder
                        }).OrderBy(mi => mi.DisplayOrder).ToList() ?? new List<MenuItemSummaryViewModel>(),
                        DisplayOrder = sectionEntity.DisplayOrder
                    }).OrderBy(ms => ms.DisplayOrder).ToList() ?? new List<MenuSectionViewModel>(),
                    DisplayOrder = menuEntity.DisplayOrder
                }).OrderBy(m => m.DisplayOrder).ToList() ?? new List<MenuViewModel>(),

                // Xử lý Reviews (ví dụ lấy 5 review mới nhất)
                Reviews = restaurant.Reviews?.OrderByDescending(r => r.ReviewDate).Take(5)
                    .Select(reviewEntity => new ReviewSummaryViewModel
                    {
                        Id = reviewEntity.Id,
                        Rating = reviewEntity.Rating,
                        Comment = reviewEntity.Comment,
                        ReviewDate = reviewEntity.ReviewDate,
                        UserDisplayName = reviewEntity.User?.DisplayName ?? "Ẩn danh",
                        UserAvatarUrl = reviewEntity.User?.AvatarUrl,
                        PhotoUrls = reviewEntity.Photos?.Select(p => p.Url).ToList() ?? new List<string>()
                    }).ToList() ?? new List<ReviewSummaryViewModel>()
            };
            return viewModel;
        }
        public async Task<EditRestaurantViewModel?> GetRestaurantForEditAsync(int restaurantId, string requestingUserId)
        {
            var restaurantEntity = await _context.Restaurants
                .Include(r => r.Address)
                .Include(r => r.OperatingHours)
                .Include(r => r.Photos) // RestaurantPhoto entities
                .Include(r => r.RestaurantCuisines) // Để lấy SelectedCuisineTypeIds
                .Include(r => r.RestaurantTags)     // Để lấy SelectedTagIds
                .AsNoTracking() // Chỉ đọc, không cần theo dõi thay đổi
                .FirstOrDefaultAsync(r => r.Id == restaurantId);

            if (restaurantEntity == null)
            {
                _logger.LogWarning("GetRestaurantForEdit: Restaurant with ID {RestaurantId} not found.", restaurantId);
                return null;
            }

            if (restaurantEntity.OwnerId != requestingUserId)
            {
                _logger.LogWarning("GetRestaurantForEdit: User {UserId} does not own Restaurant {RestaurantId}.", requestingUserId, restaurantId);
                // Cân nhắc trả về một kết quả cụ thể hơn là null để Controller biết là lỗi phân quyền
                // Ví dụ: return new EditRestaurantViewModel { IsForbidden = true }; (cần sửa ViewModel)
                // Hoặc Controller sẽ kiểm tra OwnerId một lần nữa sau khi nhận entity từ service
                // Hiện tại, trả về null, Controller sẽ coi như NotFound hoặc Forbid.
                return null;
            }

            // Lấy danh sách tất cả CuisineTypes và Tags để populate cho dropdown/checkboxes
            var allCuisines = await _context.CuisineTypes.OrderBy(c => c.Name).ToListAsync();
            var allTags = await _context.Tags.OrderBy(t => t.Name).ToListAsync();

            var viewModel = new EditRestaurantViewModel
            {
                Id = restaurantEntity.Id,
                Name = restaurantEntity.Name,
                Description = restaurantEntity.Description,
                PhoneNumber = restaurantEntity.PhoneNumber,
                Website = restaurantEntity.Website,
                MinTypicalPrice = restaurantEntity.MinTypicalPrice,
                MaxTypicalPrice = restaurantEntity.MaxTypicalPrice,
                CurrentMainImageUrl = restaurantEntity.MainImageUrl,
                // Logic lấy CurrentMainImagePublicId:
                // Nếu MainImageUrl của bạn là URL của một RestaurantPhoto có IsCover=true,
                // bạn cần tìm RestaurantPhoto đó trong restaurantEntity.Photos và lấy CloudinaryPublicId.
                // Ví dụ (cần điều chỉnh nếu MainImageUrl không trực tiếp từ RestaurantPhoto có IsCover):
                CurrentMainImagePublicId = restaurantEntity.Photos?.FirstOrDefault(p => p.Url == restaurantEntity.MainImageUrl && p.IsCover)?.CloudinaryPublicId,


                AddressId = restaurantEntity.AddressId, // Quan trọng để biết Address nào cần cập nhật
                AddressLine1 = restaurantEntity.Address.AddressLine1,
                Ward = restaurantEntity.Address.Ward,
                District = restaurantEntity.Address.District,
                City = restaurantEntity.Address.City,
                Country = restaurantEntity.Address.Country,
                Latitude = restaurantEntity.Address.Latitude,
                Longitude = restaurantEntity.Address.Longitude,

                OperatingHoursList = new List<DailyOperatingHoursInputViewModel>(), // Sẽ populate bên dưới

                CurrentOtherImages = restaurantEntity.Photos?
                    .Where(p => !p.IsCover || string.IsNullOrEmpty(restaurantEntity.MainImageUrl) || p.Url != restaurantEntity.MainImageUrl) // Lọc ra những ảnh không phải là MainImage (nếu MainImage cũng là một RestaurantPhoto)
                    .Select(p => new RestaurantPhotoViewModel
                    {
                        Id = p.Id,
                        Url = p.Url,
                        CloudinaryPublicId = p.CloudinaryPublicId,
                        IsMarkedForDeletion = false, // Mặc định
                        IsCover = p.IsCover // Giữ lại thông tin IsCover nếu có
                    }).ToList() ?? new List<RestaurantPhotoViewModel>(),

                SelectedCuisineTypeIds = restaurantEntity.RestaurantCuisines?.Select(rc => rc.CuisineTypeId).ToList() ?? new List<int>(),
                SelectedTagIds = restaurantEntity.RestaurantTags?.Select(rt => rt.TagId).ToList() ?? new List<int>(),

                AvailableCuisineTypes = allCuisines.Select(c => new SelectableCuisineTypeViewModel
                {
                    Id = c.Id,
                    Name = c.Name,
                    IconUrl = c.IconUrl,
                    IsSelected = restaurantEntity.RestaurantCuisines?.Any(rc => rc.CuisineTypeId == c.Id) ?? false
                }).ToList(),

                AvailableTags = allTags.Select(t => new SelectableTagViewModel
                {
                    Id = t.Id,
                    Name = t.Name,
                    IconUrl = t.IconUrl,
                    IsSelected = restaurantEntity.RestaurantTags?.Any(rt => rt.TagId == t.Id) ?? false
                }).ToList()
            };

            // Populate OperatingHoursList từ entity OperatingHours
            var allWeekDays = Enum.GetValues(typeof(DayOfWeek)).Cast<DayOfWeek>().OrderBy(d => (int)d); // Sắp xếp theo thứ tự ngày
            foreach (var day in allWeekDays)
            {
                var daySpecificHours = restaurantEntity.OperatingHours?
                                        .Where(oh => oh.DayOfWeek == day)
                                        .OrderBy(oh => oh.OpenTime)
                                        .ToList() ?? new List<OperatingHour>();

                var dailyInput = new DailyOperatingHoursInputViewModel { DayOfWeek = day, IsOpen = daySpecificHours.Any() };

                if (daySpecificHours.Count > 0)
                {
                    dailyInput.OpenTime1 = daySpecificHours[0].OpenTime.ToString(@"hh\:mm");
                    dailyInput.CloseTime1 = daySpecificHours[0].CloseTime.ToString(@"hh\:mm");
                    dailyInput.Notes1 = daySpecificHours[0].Notes;
                }
                if (daySpecificHours.Count > 1) // Nếu có khung giờ thứ 2
                {
                    dailyInput.OpenTime2 = daySpecificHours[1].OpenTime.ToString(@"hh\:mm");
                    dailyInput.CloseTime2 = daySpecificHours[1].CloseTime.ToString(@"hh\:mm");
                    dailyInput.Notes2 = daySpecificHours[1].Notes;
                }
                viewModel.OperatingHoursList.Add(dailyInput);
            }

            return viewModel;
        }
        public async Task<GenericResult> UpdateRestaurantAsync(EditRestaurantViewModel model, string requestingUserId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var restaurantToUpdate = await _context.Restaurants
                    .Include(r => r.Address)
                    .Include(r => r.OperatingHours) // QUAN TRỌNG: Include OperatingHours để có thể xóa
                    .Include(r => r.Photos)
                    .Include(r => r.RestaurantCuisines)
                    .Include(r => r.RestaurantTags)
                    .FirstOrDefaultAsync(r => r.Id == model.Id);

                if (restaurantToUpdate == null)
                {
                    await transaction.RollbackAsync();
                    return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy nhà hàng để cập nhật." };
                }

                if (restaurantToUpdate.OwnerId != requestingUserId)
                {
                    await transaction.RollbackAsync();
                    _logger.LogWarning("UpdateRestaurantAsync: User {UserId} attempted to update restaurant {RestaurantId} not owned by them.", requestingUserId, model.Id);
                    return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền chỉnh sửa nhà hàng này." };
                }

                // 1. Cập nhật thông tin cơ bản của Restaurant Entity (như trước)
                restaurantToUpdate.Name = model.Name;
                restaurantToUpdate.Description = model.Description;
                restaurantToUpdate.PhoneNumber = model.PhoneNumber;
                restaurantToUpdate.Website = model.Website;
                restaurantToUpdate.MinTypicalPrice = model.MinTypicalPrice;
                restaurantToUpdate.MaxTypicalPrice = model.MaxTypicalPrice;
                restaurantToUpdate.UpdatedAt = DateTime.UtcNow;

                // 2. Cập nhật Address Entity (như trước)
                if (restaurantToUpdate.Address == null)
                {
                    var existingAddress = await _context.Addresses.FindAsync(model.AddressId);
                    if (existingAddress == null)
                    {
                        await transaction.RollbackAsync();
                        return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy thông tin địa chỉ liên quan." };
                    }
                    restaurantToUpdate.Address = existingAddress;
                }
                restaurantToUpdate.Address.AddressLine1 = model.AddressLine1;
                restaurantToUpdate.Address.Ward = model.Ward;
                restaurantToUpdate.Address.District = model.District;
                restaurantToUpdate.Address.City = model.City;
                restaurantToUpdate.Address.Country = string.IsNullOrWhiteSpace(model.Country) ? "Việt Nam" : model.Country;
                restaurantToUpdate.Address.Latitude = model.Latitude;
                restaurantToUpdate.Address.Longitude = model.Longitude;

                // --- 3. CẬP NHẬT OPERATING HOURS ---
                _context.OperatingHours.RemoveRange(restaurantToUpdate.OperatingHours);

                // Thêm lại OperatingHours mới từ ViewModel
                var newOperatingHours = new List<OperatingHour>(); // Tạo list mới
                if (model.OperatingHoursList != null)
                {
                    foreach (var ohInput in model.OperatingHoursList.Where(oh => oh.IsOpen)) // Chỉ lấy những ngày được đánh dấu IsOpen
                    {
                        void AddOperatingHourIfValid(string? openTimeStr, string? closeTimeStr, string? notes)
                        {
                            if (!string.IsNullOrWhiteSpace(openTimeStr) &&
                                !string.IsNullOrWhiteSpace(closeTimeStr) &&
                                TimeSpan.TryParseExact(openTimeStr, @"hh\:mm", CultureInfo.InvariantCulture, out TimeSpan openTs) &&
                                TimeSpan.TryParseExact(closeTimeStr, @"hh\:mm", CultureInfo.InvariantCulture, out TimeSpan closeTs))
                            {
                                // Thêm validation nếu openTs >= closeTs (trừ trường hợp qua đêm, cần logic phức tạp hơn)
                                if (openTs >= closeTs && !(closeTs < TimeSpan.FromHours(6) && openTs > TimeSpan.FromHours(18))) // Ví dụ đơn giản cho qua đêm
                                {
                                    _logger.LogWarning("Invalid time range for restaurant {RestaurantId}, day {DayOfWeek}: Open {OpenTime} - Close {CloseTime}", restaurantToUpdate.Id, ohInput.DayOfWeek, openTs, closeTs);
                                    return;
                                }

                                newOperatingHours.Add(new OperatingHour
                                {
                                    Restaurant = restaurantToUpdate,
                                    DayOfWeek = ohInput.DayOfWeek,
                                    OpenTime = openTs,
                                    CloseTime = closeTs,
                                    Notes = notes
                                });
                            }
                        }
                        AddOperatingHourIfValid(ohInput.OpenTime1, ohInput.CloseTime1, ohInput.Notes1);
                        AddOperatingHourIfValid(ohInput.OpenTime2, ohInput.CloseTime2, ohInput.Notes2);
                    }
                }
                restaurantToUpdate.OperatingHours = newOperatingHours;

                // 4. Xử lý Ảnh (MainImage và OtherImages
                bool anyImageProcessingError = false;

                // 4a. Xóa các "OtherImages" được đánh dấu xóa
                if (model.CurrentOtherImages != null)
                {
                    var photosToDeleteInDb = new List<RestaurantPhoto>();
                    foreach (var imgVm in model.CurrentOtherImages.Where(i => i.IsMarkedForDeletion))
                    {
                        var photoEntity = restaurantToUpdate.Photos.FirstOrDefault(p => p.Id == imgVm.Id);
                        if (photoEntity != null)
                        {
                            if (!string.IsNullOrEmpty(photoEntity.CloudinaryPublicId))
                            {
                                var deleteResult = await _photoService.DeletePhotoAsync(photoEntity.CloudinaryPublicId);
                                if (!deleteResult.Success)
                                {
                                    _logger.LogWarning("Không thể xóa ảnh gallery cũ (PublicId: {PublicId}) trên Cloudinary cho nhà hàng ID {RestaurantId}. Lỗi: {Error}",
                                        photoEntity.CloudinaryPublicId, restaurantToUpdate.Id, deleteResult.ErrorMessage);
                                    // Quyết định: Có rollback transaction không? Hay chỉ log lỗi và tiếp tục?
                                    // Để an toàn, nếu không xóa được trên cloud thì không nên xóa ở DB.
                                    // Hoặc có thể đánh dấu là "cần xóa thủ công"
                                    anyImageProcessingError = true; // Đánh dấu lỗi
                                                                    // continue; // Bỏ qua việc xóa khỏi DB nếu xóa trên cloud thất bại
                                }
                            }
                            photosToDeleteInDb.Add(photoEntity);
                        }
                    }
                    if (photosToDeleteInDb.Any())
                    {
                        _context.RestaurantPhotos.RemoveRange(photosToDeleteInDb);
                    }
                }

                // 4b. Xử lý MainImageFile mới
                if (model.NewMainImageFile != null && model.NewMainImageFile.Length > 0)
                {
                    // (Tùy chọn) Xóa MainImage cũ trên Cloudinary nếu nó được quản lý qua CloudinaryPublicId
                    // Điều này phụ thuộc vào cách bạn lưu MainImage.
                    // Nếu MainImageUrl của Restaurant trỏ đến một RestaurantPhoto có IsCover=true:
                    var currentCoverPhoto = restaurantToUpdate.Photos.FirstOrDefault(p => p.IsCover && p.Url == restaurantToUpdate.MainImageUrl);
                    if (currentCoverPhoto != null && !string.IsNullOrEmpty(currentCoverPhoto.CloudinaryPublicId))
                    {
                        await _photoService.DeletePhotoAsync(currentCoverPhoto.CloudinaryPublicId);
                        _context.RestaurantPhotos.Remove(currentCoverPhoto); // Xóa RestaurantPhoto cũ khỏi DB
                    }
                    // Hoặc nếu bạn có trường Restaurant.MainImagePublicId riêng:
                    // if (!string.IsNullOrEmpty(restaurantToUpdate.MainImagePublicId))
                    // {
                    //     await _photoService.DeletePhotoAsync(restaurantToUpdate.MainImagePublicId);
                    // }


                    string mainImageFolder = $"restaurants/{restaurantToUpdate.Id}/main"; // Thư mục rõ ràng hơn
                    var mainUploadResult = await _photoService.UploadPhotoAsync(model.NewMainImageFile, mainImageFolder);

                    if (mainUploadResult.Success && mainUploadResult.Url != null && mainUploadResult.PublicId != null)
                    {
                        restaurantToUpdate.MainImageUrl = mainUploadResult.Url;
                        // Nếu bạn muốn MainImage cũng là một RestaurantPhoto:
                        // Xóa tất cả các ảnh IsCover=true cũ (nếu có)
                        foreach (var p in restaurantToUpdate.Photos.Where(ph => ph.IsCover)) p.IsCover = false;
                        // Thêm MainImage mới như một RestaurantPhoto và đánh dấu IsCover
                        var newMainRestaurantPhoto = new RestaurantPhoto
                        {
                            Url = mainUploadResult.Url,
                            CloudinaryPublicId = mainUploadResult.PublicId,
                            RestaurantId = restaurantToUpdate.Id, // Hoặc Restaurant = restaurantToUpdate,
                            IsCover = true,
                            UploadedDate = DateTime.UtcNow,
                            Caption = "Ảnh đại diện"
                        };
                        // _context.RestaurantPhotos.Add(newMainRestaurantPhoto); // Hoặc thêm vào collection
                        restaurantToUpdate.Photos.Add(newMainRestaurantPhoto);
                    }
                    else
                    {
                        _logger.LogError("Lỗi tải ảnh đại diện mới cho nhà hàng {RestaurantName}: {ErrorMessage}", model.Name, mainUploadResult.ErrorMessage);
                        // Nếu việc tải ảnh đại diện là bắt buộc phải thành công để tiếp tục, thì rollback và báo lỗi
                        await transaction.RollbackAsync();
                        return new GenericResult { Success = false, ErrorMessage = $"Lỗi tải ảnh đại diện: {mainUploadResult.ErrorMessage}" };
                    }
                }

                // 4c. Upload OtherImageFiles mới
                if (model.NewOtherImageFiles != null)
                {
                    string galleryFolder = $"restaurants/{restaurantToUpdate.Id}/gallery";
                    foreach (var file in model.NewOtherImageFiles)
                    {
                        if (file != null && file.Length > 0)
                        {
                            var galleryUploadResult = await _photoService.UploadPhotoAsync(file, galleryFolder);
                            if (galleryUploadResult.Success && galleryUploadResult.Url != null && galleryUploadResult.PublicId != null)
                            {
                                restaurantToUpdate.Photos.Add(new RestaurantPhoto
                                {
                                    Url = galleryUploadResult.Url,
                                    CloudinaryPublicId = galleryUploadResult.PublicId,
                                    RestaurantId = restaurantToUpdate.Id, // Hoặc Restaurant = restaurantToUpdate,
                                    IsCover = false, // Ảnh gallery không phải ảnh bìa
                                    UploadedDate = DateTime.UtcNow,
                                    Caption = file.FileName // Hoặc một caption khác
                                });
                            }
                            else
                            {
                                _logger.LogWarning("Lỗi tải ảnh gallery '{FileName}' cho restaurant ID {RestaurantId}: {ErrorMessage}", file.FileName, restaurantToUpdate.Id, galleryUploadResult.ErrorMessage);
                                anyImageProcessingError = true; // Chỉ đánh dấu, không rollback ngay để thử các ảnh khác
                            }
                        }
                    }
                }

                if (anyImageProcessingError)
                {
                    // Nếu có bất kỳ lỗi nào trong quá trình xử lý ảnh phụ, quyết định rollback hay không.
                    // Để an toàn, có thể rollback nếu việc upload ảnh là quan trọng.
                    await transaction.RollbackAsync();
                    return new GenericResult { Success = false, ErrorMessage = "Đã xảy ra lỗi khi xử lý một số hình ảnh. Vui lòng thử lại." };
                }

                // 5. Cập nhật RestaurantCuisines
                if (restaurantToUpdate.RestaurantCuisines.Any()) // Chỉ remove nếu có
                {
                    _context.RestaurantCuisines.RemoveRange(restaurantToUpdate.RestaurantCuisines);
                }

                // Thêm lại các RestaurantCuisine mới từ ViewModel
                if (model.SelectedCuisineTypeIds != null && model.SelectedCuisineTypeIds.Any())
                {
                    var newRestaurantCuisines = new List<RestaurantCuisine>();
                    foreach (var cuisineId in model.SelectedCuisineTypeIds)
                    {
                        // Kiểm tra xem CuisineType Id có hợp lệ không (tồn tại trong DB)
                        if (await _context.CuisineTypes.AnyAsync(ct => ct.Id == cuisineId))
                        {
                            newRestaurantCuisines.Add(new RestaurantCuisine
                            {
                                RestaurantId = restaurantToUpdate.Id, // Gán RestaurantId
                                CuisineTypeId = cuisineId
                            });
                        }
                        else
                        {
                            _logger.LogWarning("UpdateRestaurantAsync: CuisineType ID {CuisineId} không hợp lệ được chọn cho Restaurant ID {RestaurantId}.", cuisineId, restaurantToUpdate.Id);
                        }
                    }
                    if (newRestaurantCuisines.Any())
                    {
                        await _context.RestaurantCuisines.AddRangeAsync(newRestaurantCuisines);
                    }
                }

                // 6. Cập nhật RestaurantTags
                if (restaurantToUpdate.RestaurantTags.Any())
                {
                    _context.RestaurantTags.RemoveRange(restaurantToUpdate.RestaurantTags);
                }

                // Thêm lại các RestaurantTag mới từ ViewModel
                if (model.SelectedTagIds != null && model.SelectedTagIds.Any())
                {
                    var newRestaurantTags = new List<RestaurantTag>();
                    foreach (var tagId in model.SelectedTagIds)
                    {
                        // Kiểm tra xem Tag Id có hợp lệ không
                        if (await _context.Tags.AnyAsync(t => t.Id == tagId))
                        {
                            newRestaurantTags.Add(new RestaurantTag
                            {
                                RestaurantId = restaurantToUpdate.Id, // Gán RestaurantId
                                TagId = tagId
                            });
                        }
                        else
                        {
                            _logger.LogWarning("UpdateRestaurantAsync: Tag ID {TagId} không hợp lệ được chọn cho Restaurant ID {RestaurantId}.", tagId, restaurantToUpdate.Id);
                        }
                    }
                    if (newRestaurantTags.Any())
                    {
                        await _context.RestaurantTags.AddRangeAsync(newRestaurantTags);
                    }
                }

                await _context.SaveChangesAsync(); // Lưu tất cả thay đổi (Restaurant, Address, OperatingHours mới, xóa OperatingHours cũ)
                await transaction.CommitAsync();

                _logger.LogInformation("Nhà hàng '{RestaurantName}' (ID: {RestaurantId}) được cập nhật thành công bởi User ID: {OwnerId}", restaurantToUpdate.Name, restaurantToUpdate.Id, requestingUserId);
                return new GenericResult { Success = true };
            }
            catch (DbUpdateConcurrencyException dbConcEx)
            {
                await transaction.RollbackAsync();
                _logger.LogError(dbConcEx, "Lỗi tương tranh khi cập nhật nhà hàng ID {RestaurantId}", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Dữ liệu có thể đã được người khác thay đổi. Vui lòng tải lại và thử lại." };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Lỗi không mong muốn khi cập nhật nhà hàng ID {RestaurantId}", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Đã xảy ra lỗi hệ thống khi cập nhật nhà hàng." };
            }
        }
        public async Task<IPagedList<Restaurant>> SearchRestaurantsAdvancedAsync(
                string? searchTerm = null,
                string? addressQuery = null,
                double? latitude = null,
                double? longitude = null,
                double? radiusInKm = 5.0,
                IEnumerable<int>? cuisineTypeIds = null,
                IEnumerable<int>? tagIds = null,
                decimal? minPrice = null,
                decimal? maxPrice = null,
                string? sortBy = null,
                int page = 1,
                int pageSize = 10
            )
        {
            // Only include essential data for search results - remove heavy collections
            var query = _context.Restaurants
                .Include(r => r.Address)
                .Include(r => r.RestaurantCuisines)
                    .ThenInclude(rc => rc.CuisineType)
                .Include(r => r.RestaurantTags)
                    .ThenInclude(rt => rt.Tag)
                .Include(r => r.OperatingHours)
                .AsQueryable();

            // Apply text search if provided
            if (!string.IsNullOrEmpty(searchTerm))
            {
                if (searchTerm.Length < 3)
                {
                    _logger.LogWarning("Độ dài < 3 là quá ngắn để có ý nghĩa: {searchTerm}", searchTerm);
                    // Return empty paged list for invalid search terms
                    return new StaticPagedList<Restaurant>(new List<Restaurant>(), page, pageSize, 0);
                }

                // Normalize search term to lower case for case-insensitive comparison
                searchTerm = searchTerm.ToLower();                // Apply text search filtering (removed MenuItems search for performance)
                query = query.Where(r =>
                    r.Name.ToLower().Contains(searchTerm) ||
                    r.Description.ToLower().Contains(searchTerm) ||
                    r.RestaurantCuisines.Any(rc => rc.CuisineType.Name.ToLower().Contains(searchTerm)) ||
                    r.RestaurantTags.Any(rt => rt.Tag.Name.ToLower().Contains(searchTerm))
                );
            }            // Apply address text search if provided
            if (!string.IsNullOrEmpty(addressQuery))
            {
                // Special case: Skip address filtering when using current location
                // since we'll be filtering by coordinates instead
                if (addressQuery == "Vị trí hiện tại của bạn")
                {
                    _logger.LogInformation("Skipping address text search for current location placeholder");
                }
                else
                {
                    // Normalize search term to lower case and trim for better matching
                    string normalizedAddressQuery = addressQuery.ToLower().Trim();

                    // Check if the address query contains commas, indicating it might be a full address
                    if (normalizedAddressQuery.Contains(','))
                    {
                        // Split the address into parts (street, ward, district, city)
                        var addressParts = normalizedAddressQuery.Split(',')
                            .Select(part => part.Trim())
                            .Where(part => !string.IsNullOrEmpty(part))
                            .ToList();
                        // Create a more precise query that tries to match all parts of the address
                        // We can't use FullAddress in EF Core query - it's not mapped
                        query = query.Where(r =>
                            r.Address != null &&
                            // Match individual parts against appropriate address fields
                            addressParts.All(part =>
                                r.Address.AddressLine1.ToLower().Contains(part) ||
                                r.Address.Ward.ToLower().Contains(part) ||
                                r.Address.District.ToLower().Contains(part) ||
                                r.Address.City.ToLower().Contains(part) ||
                                r.Address.Country.ToLower().Contains(part))
                        );
                    }
                    else
                    {                    // For simpler queries, use the standard approach but with improved matching
                        query = query.Where(r =>
                            r.Address != null && (
                                r.Address.AddressLine1.ToLower().Contains(normalizedAddressQuery) ||
                                r.Address.Ward.ToLower().Contains(normalizedAddressQuery) ||
                                r.Address.District.ToLower().Contains(normalizedAddressQuery) ||
                                r.Address.City.ToLower().Contains(normalizedAddressQuery) ||
                                r.Address.Country.ToLower().Contains(normalizedAddressQuery)
                            // Removed FullAddress check as it's not mapped to the database
                            )
                        );
                    }

                    _logger.LogInformation("Applied address search for: {AddressQuery}", addressQuery);
                }
            }

            // Apply cuisine filters
            if (cuisineTypeIds != null && cuisineTypeIds.Any())
            {
                query = query.Where(r =>
                    r.RestaurantCuisines.Any(rc => cuisineTypeIds.Contains(rc.CuisineTypeId)));
            }

            // Apply tag filters
            if (tagIds != null && tagIds.Any())
            {
                query = query.Where(r =>
                    r.RestaurantTags.Any(rt => tagIds.Contains(rt.TagId)));
            }

            // Apply price filters
            if (minPrice.HasValue)
            {
                query = query.Where(r => r.MaxTypicalPrice >= minPrice.Value);
            }

            if (maxPrice.HasValue)
            {
                query = query.Where(r => r.MinTypicalPrice <= maxPrice.Value);
            }

            // Apply sorting 
            if (!string.IsNullOrEmpty(sortBy))
            {
                query = sortBy.ToLower() switch
                {
                    "highestrated" => query.OrderByDescending(r => r.AverageRating),
                    "mostreviewed" => query.OrderByDescending(r => r.ReviewCount),
                    "relevance" => query.OrderByDescending(r => r.AverageRating * 0.7 + r.ReviewCount * 0.3),
                    _ => query.OrderByDescending(r => r.AverageRating)
                };
            }
            else
            {
                // Default sorting - use relevance formula for consistent behavior
                query = query.OrderByDescending(r => r.AverageRating * 0.7 + r.ReviewCount * 0.3);
            }

            // If we have coordinates, we need to filter and sort by distance in memory
            List<Restaurant> finalResults;
            int totalCount;

            if (latitude.HasValue && longitude.HasValue)
            {
                double searchLat = latitude.Value;
                double searchLng = longitude.Value;
                double searchRadius = radiusInKm ?? 5.0;

                // Execute base query to get filtered results before distance calculation
                var filteredRestaurants = await query.ToListAsync();                // Calculate distances and apply distance filter
                var restaurantsWithDistance = filteredRestaurants
                    .Where(r => r.Address != null && r.Address.Latitude.HasValue && r.Address.Longitude.HasValue)
                    .Select(r => new
                    {
                        Restaurant = r,
                        Distance = CalculateDistance(
                            searchLat,
                            searchLng,
                            r.Address.Latitude!.Value,
                            r.Address.Longitude!.Value)
                    })
                    .Where(x => x.Distance <= searchRadius)
                    // Chỉ sắp xếp theo khoảng cách khi sortBy rỗng hoặc là "distance"
                    .ToList();
                //log ghi ra tất cả nhà hàng để biết số lượng nhà hàng
                _logger.LogInformation($"Tổng số nhà hàng tìm thấy: {restaurantsWithDistance.Count}");

                totalCount = restaurantsWithDistance.Count;                // Áp dụng sắp xếp dựa trên tuỳ chọn người dùng (không ưu tiên khoảng cách)
                var sortedResults = sortBy?.ToLower() switch
                {
                    "highestrated" => restaurantsWithDistance.OrderByDescending(x => x.Restaurant.AverageRating),
                    "mostreviewed" => restaurantsWithDistance.OrderByDescending(x => x.Restaurant.ReviewCount),
                    "relevance" => restaurantsWithDistance.OrderByDescending(x => x.Restaurant.AverageRating * 0.7 + x.Restaurant.ReviewCount * 0.3),
                    _ => restaurantsWithDistance.OrderByDescending(x => x.Restaurant.AverageRating * 0.7 + x.Restaurant.ReviewCount * 0.3) // Mặc định theo relevance
                };

                // Apply pagination
                finalResults = sortedResults
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(x => x.Restaurant)
                    .ToList();
            }
            else
            {
                // No geo filtering needed, execute query directly with pagination
                totalCount = await query.CountAsync();
                finalResults = await query
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();
            }

            // Return as paged list
            return new StaticPagedList<Restaurant>(finalResults, page, pageSize, totalCount);
        }
        // Helper method to calculate distance between two coordinates using the Haversine formula
        private double CalculateDistance(double lat1, double lon1, double lat2, double lon2)
        {
            const double EarthRadiusKm = 6371.0; // Earth's radius in kilometers

            // Convert degrees to radians
            var dLat = ToRadians(lat2 - lat1);
            var dLon = ToRadians(lon2 - lon1);

            // Haversine formula
            var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                    Math.Cos(ToRadians(lat1)) * Math.Cos(ToRadians(lat2)) *
                    Math.Sin(dLon / 2) * Math.Sin(dLon / 2);

            var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
            var distance = EarthRadiusKm * c;

            return distance; // Distance in kilometers
        }
        private double ToRadians(double degrees)
        {
            return degrees * (Math.PI / 180);
        }
        public async Task<int> GetRestaurantCountByOwnerIdAsync(string userId)
        {
            return await _context.Restaurants
                .Where(r => r.OwnerId == userId)
                .CountAsync();
        }/// <summary>
         /// Chuẩn hóa địa chỉ và tọa độ với giá trị mặc định cho Đà Nẵng
         /// </summary>
        public async Task<(string address, double latitude, double longitude, double radiusInKm)> NormalizeLocationParameters(
            string? address, double? latitude = null, double? longitude = null, string? maxDistance = null)
        {
            // Mặc định địa chỉ là Đà Nẵng nếu không có địa chỉ
            if (string.IsNullOrEmpty(address))
            {
                address = "Đà Nẵng";
            }

            double defaultRadius = 5.0;
            if (!string.IsNullOrEmpty(maxDistance) && double.TryParse(maxDistance, out double radius))
            {
                defaultRadius = radius;
            }

            // Special case: If address is "Vị trí hiện tại của bạn" and we have coordinates, use them directly
            if (address == "Vị trí hiện tại của bạn" && latitude.HasValue && longitude.HasValue)
            {
                _logger.LogInformation("Using provided coordinates for current location: ({Lat}, {Lng})",
                    latitude.Value, longitude.Value);
                return (address, latitude.Value, longitude.Value, defaultRadius);
            }

            // If we have explicit coordinates for any other address, use those
            if (latitude.HasValue && longitude.HasValue)
            {
                return (address, latitude.Value, longitude.Value, defaultRadius);
            }

            // If we don't have coordinates but have an address, use the GeoLocationService
            if (_geoLocationService != null)
            {
                try
                {
                    // Use the specialized Vietnamese location method for better accuracy
                    var coords = await _geoLocationService.GetVietnameseLocationCoordinatesAsync(address!);

                    _logger.LogInformation("Vietnamese address '{Address}' geocoded to coordinates: ({Lat}, {Lng})",
                        address, coords.latitude, coords.longitude);

                    return (address, coords.latitude, coords.longitude, defaultRadius);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error geocoding address '{Address}', using default coordinates", address);
                }
            }

            // Fallback to default coordinates for Đà Nẵng
            double normalizedLatitude = 16.047079; // Tọa độ trung tâm Đà Nẵng
            double normalizedLongitude = 108.206230;

            return (address, normalizedLatitude, normalizedLongitude, defaultRadius);
        }
        public Task<IPagedList<Restaurant>> GetRestaurantByOwnerIdAsync(string ownerId, int page, int pageSize)
        {
            //get all restaurants owned by the user with the User.Id = ownerId
            //and return paginated list
            return _context.Restaurants
                .Where(r => r.OwnerId == ownerId)
                .OrderByDescending(r => r.CreatedAt)
                .ToPagedListAsync(page, pageSize);
        }
        public async Task<RestaurantCreationResult> CreateRestaurantAsync(RegisterRestaurantViewModel model, string ownerId)
        {
            var owner = await _userManager.FindByIdAsync(ownerId);
            if (owner == null)
            {
                _logger.LogWarning("Attempt to create restaurant with invalid ownerId: {OwnerId}", ownerId);
                return new RestaurantCreationResult { Success = false, ErrorMessage = "Người dùng không hợp lệ để tạo nhà hàng." };
            }

            // (Tùy chọn) Kiểm tra tên nhà hàng unique nếu cần
            // if (await _context.Restaurants.AnyAsync(r => r.Name.ToLower() == model.Name.ToLower()))
            // {
            //    return new RestaurantCreationResult { Success = false, ErrorMessage = $"Tên nhà hàng '{model.Name}' đã tồn tại." };
            // }

            using (var transaction = await _context.Database.BeginTransactionAsync())
            {
                try
                {
                    // 1. Tạo Address
                    var address = new Address
                    {
                        AddressLine1 = model.AddressLine1,
                        Ward = model.Ward,
                        District = model.District,
                        City = model.City,
                        Country = string.IsNullOrWhiteSpace(model.Country) ? "Việt Nam" : model.Country,
                        Latitude = model.Latitude,
                        Longitude = model.Longitude,
                    };
                    _context.Addresses.Add(address);
                    // Sẽ SaveChanges sau cùng hoặc khi cần Address.Id cho bước nào đó mà EF không tự link được

                    // 2. Tạo Restaurant
                    var restaurant = new Restaurant
                    {
                        Name = model.Name,
                        Description = model.Description,
                        PhoneNumber = model.PhoneNumber,
                        Website = model.Website,
                        MinTypicalPrice = model.MinTypicalPrice,
                        MaxTypicalPrice = model.MaxTypicalPrice,
                        Status = RestaurantStatus.Open, // Hoặc PendingApproval
                        OwnerId = ownerId,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        Address = address // EF Core sẽ tự động gán AddressId khi lưu Restaurant nếu Address đã được Add vào context
                    };

                    // 3. Thêm OperatingHours
                    if (model.OperatingHoursList != null)
                    {
                        foreach (var ohInput in model.OperatingHoursList.Where(oh => oh.IsOpen))
                        {
                            void AddOperatingHourIfValid(string? openTimeStr, string? closeTimeStr, string? notes)
                            {
                                if (!string.IsNullOrWhiteSpace(openTimeStr) &&
                                    !string.IsNullOrWhiteSpace(closeTimeStr) &&
                                    TimeSpan.TryParseExact(openTimeStr, "HH\\:mm", CultureInfo.InvariantCulture, out TimeSpan openTs) &&
                                    TimeSpan.TryParseExact(closeTimeStr, "HH\\:mm", CultureInfo.InvariantCulture, out TimeSpan closeTs))
                                {
                                    // Thêm logic validation thời gian phức tạp hơn ở đây
                                    // Ví dụ: closeTs > openTs (trừ trường hợp qua đêm)
                                    // Hoặc đảm bảo khung 2 sau khung 1
                                    restaurant.OperatingHours.Add(new OperatingHour
                                    {
                                        Restaurant = restaurant, // Liên kết trực tiếp
                                        DayOfWeek = ohInput.DayOfWeek,
                                        OpenTime = openTs,
                                        CloseTime = closeTs,
                                        Notes = notes
                                    });
                                }
                            }
                            AddOperatingHourIfValid(ohInput.OpenTime1, ohInput.CloseTime1, ohInput.Notes1);
                            AddOperatingHourIfValid(ohInput.OpenTime2, ohInput.CloseTime2, ohInput.Notes2);
                        }
                    }
                    _context.Restaurants.Add(restaurant); // Add restaurant (và các OperatingHours, Address liên quan) vào context
                    await _context.SaveChangesAsync();    // LƯU LẦN 1: Để lấy restaurant.Id và address.Id

                    // 4. Xử lý Upload Ảnh (sau khi đã có restaurant.Id)
                    bool imageErrorOccurred = false;

                    // Main Image
                    if (model.MainImageFile != null && model.MainImageFile.Length > 0)
                    {
                        string mainImageFolder = $"restaurants/{restaurant.Id}/main_image";
                        var mainUploadResult = await _photoService.UploadPhotoAsync(model.MainImageFile, mainImageFolder);
                        if (mainUploadResult.Success && mainUploadResult.Url != null && mainUploadResult.PublicId != null)
                        {
                            restaurant.MainImageUrl = mainUploadResult.Url;
                            // Bạn có thể tạo một RestaurantPhoto cho MainImage nếu muốn quản lý nó như các ảnh khác
                            // var mainRestaurantPhoto = new RestaurantPhoto { ... RestaurantId = restaurant.Id, IsCover = true ...};
                            // _context.RestaurantPhotos.Add(mainRestaurantPhoto);
                        }
                        else
                        {
                            _logger.LogError("Lỗi tải ảnh đại diện cho nhà hàng {RestaurantName}: {ErrorMessage}", model.Name, mainUploadResult.ErrorMessage);
                            imageErrorOccurred = true; // Đánh dấu có lỗi ảnh
                                                       // Không rollback ngay, cho phép thử upload các ảnh khác nếu muốn,
                                                       // nhưng cuối cùng sẽ rollback nếu imageErrorOccurred là true
                        }
                    }

                    // Other Images
                    if (model.OtherImageFiles != null && model.OtherImageFiles.Any())
                    {
                        string galleryFolder = $"restaurants/{restaurant.Id}/gallery";
                        foreach (var file in model.OtherImageFiles)
                        {
                            if (file != null && file.Length > 0)
                            {
                                var galleryUploadResult = await _photoService.UploadPhotoAsync(file, galleryFolder);
                                if (galleryUploadResult.Success && galleryUploadResult.Url != null && galleryUploadResult.PublicId != null)
                                {
                                    var restaurantPhoto = new RestaurantPhoto
                                    {
                                        Url = galleryUploadResult.Url,
                                        CloudinaryPublicId = galleryUploadResult.PublicId,
                                        RestaurantId = restaurant.Id, // Gán RestaurantId
                                        UploadedDate = DateTime.UtcNow,
                                        Caption = file.FileName // Hoặc một caption khác
                                    };
                                    _context.RestaurantPhotos.Add(restaurantPhoto);
                                }
                                else
                                {
                                    _logger.LogError("Lỗi tải ảnh gallery '{FileName}' cho nhà hàng {RestaurantName}: {ErrorMessage}", file.FileName, model.Name, galleryUploadResult.ErrorMessage);
                                    imageErrorOccurred = true; // Đánh dấu có lỗi ảnh
                                }
                            }
                        }
                    }

                    if (imageErrorOccurred) // Nếu có bất kỳ lỗi nào khi upload ảnh
                    {
                        await transaction.RollbackAsync();
                        return new RestaurantCreationResult { Success = false, ErrorMessage = "Đã xảy ra lỗi trong quá trình tải ảnh lên. Vui lòng thử lại." };
                    }

                    // Nếu có thay đổi ở restaurant (MainImageUrl) hoặc thêm RestaurantPhotos, cần SaveChanges
                    if (_context.ChangeTracker.HasChanges()) // Kiểm tra xem có gì để lưu không
                    {
                        await _context.SaveChangesAsync(); // LƯU LẦN 2: Lưu MainImageUrl và RestaurantPhotos
                    }


                    // 5. Xử lý RestaurantCuisine
                    if (model.SelectedCuisineTypeIds != null && model.SelectedCuisineTypeIds.Any())
                    {
                        foreach (var cuisineId in model.SelectedCuisineTypeIds)
                        {
                            if (await _context.CuisineTypes.AnyAsync(ct => ct.Id == cuisineId))
                            {
                                _context.RestaurantCuisines.Add(new RestaurantCuisine { RestaurantId = restaurant.Id, CuisineTypeId = cuisineId });
                            }
                        }
                    }

                    // 6. Xử lý RestaurantTag
                    if (model.SelectedTagIds != null && model.SelectedTagIds.Any())
                    {
                        foreach (var tagId in model.SelectedTagIds)
                        {
                            if (await _context.Tags.AnyAsync(t => t.Id == tagId))
                            {
                                _context.RestaurantTags.Add(new RestaurantTag { RestaurantId = restaurant.Id, TagId = tagId });
                            }
                        }
                    }

                    // Kiểm tra lại lần nữa trước khi SaveChanges cuối cho bảng nối
                    if (_context.ChangeTracker.HasChanges())
                    {
                        await _context.SaveChangesAsync(); // LƯU LẦN 3: Lưu các bảng nối
                    }

                    await transaction.CommitAsync();
                    _logger.LogInformation("Nhà hàng '{RestaurantName}' (ID: {RestaurantId}) được tạo thành công bởi User ID: {OwnerId}", restaurant.Name, restaurant.Id, ownerId);
                    return new RestaurantCreationResult { Success = true, CreatedRestaurantId = restaurant.Id };
                }
                catch (DbUpdateException dbEx)
                {
                    await transaction.RollbackAsync();
                    _logger.LogError(dbEx, "Lỗi DbUpdateException khi tạo nhà hàng cho OwnerId {OwnerId}. Model: {@RegisterModel}", ownerId, model);
                    return new RestaurantCreationResult { Success = false, ErrorMessage = "Lỗi cơ sở dữ liệu khi lưu thông tin. Vui lòng thử lại." };
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    _logger.LogError(ex, "Lỗi không mong muốn khi tạo nhà hàng cho OwnerId {OwnerId}. Model: {@RegisterModel}", ownerId, model);
                    return new RestaurantCreationResult { Success = false, ErrorMessage = "Đã xảy ra lỗi hệ thống. Vui lòng thử lại sau." };
                }
            }
        }
        public async Task<(bool IsValid, string? RestaurantName)> ValidateRestaurantOwnershipAsync(int restaurantId, string ownerId)
        {
            var restaurant = await _context.Restaurants
                                        .AsNoTracking()
                                        .Where(r => r.Id == restaurantId && r.OwnerId == ownerId)
                                        .Select(r => new { r.Name }) // Chỉ lấy tên để tối ưu
                                        .FirstOrDefaultAsync();

            if (restaurant != null)
            {
                return (true, restaurant.Name);
            }
            return (false, null);
        }
        public async Task<PagedResult<AdminRestaurantListItemViewModel>> GetAllRestaurantsForAdminAsync(
string? searchTerm = null,
RestaurantStatus? statusFilter = null,
string? ownerSearchTerm = null,
string? sortBy = null,
int pageNumber = 1,
int pageSize = 10)
        {
            var query = _context.Restaurants
                                .Include(r => r.Owner)  // Để lấy thông tin Owner
                                .Include(r => r.Address)
                                .AsQueryable();

            // Lọc theo trạng thái
            if (statusFilter.HasValue)
            {
                query = query.Where(r => r.Status == statusFilter.Value);
            }

            // Lọc theo searchTerm (tên nhà hàng, mô tả)
            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                var term = searchTerm.ToLower().Trim();
                query = query.Where(r => EF.Functions.Like(r.Name.ToLower(), $"%{term}%") ||
                                         (r.Description != null && EF.Functions.Like(r.Description.ToLower(), $"%{term}%")));
            }

            // Lọc theo thông tin chủ sở hữu
            if (!string.IsNullOrWhiteSpace(ownerSearchTerm))
            {
                var ownerTerm = ownerSearchTerm.ToLower().Trim();
                query = query.Where(r => r.OwnerId != null &&
                                         (EF.Functions.Like(r.Owner.UserName.ToLower(), $"%{ownerTerm}%") ||
                                          EF.Functions.Like(r.Owner.Email.ToLower(), $"%{ownerTerm}%") ||
                                          (r.Owner.DisplayName != null && EF.Functions.Like(r.Owner.DisplayName.ToLower(), $"%{ownerTerm}%"))
                                         ));
            }

            // Sắp xếp
            sortBy = sortBy?.ToLower().Trim() ?? "createdat_desc"; // Mặc định mới nhất
            switch (sortBy)
            {
                case "name_asc":
                    query = query.OrderBy(r => r.Name);
                    break;
                case "owner_asc":
                    query = query.OrderBy(r => r.Owner != null ? r.Owner.UserName : string.Empty);
                    break;
                case "status_asc":
                    query = query.OrderBy(r => r.Status);
                    break;
                default: // createdat_desc
                    query = query.OrderByDescending(r => r.CreatedAt);
                    break;
            }

            var totalCount = await query.CountAsync();
            var restaurants = await query
                                    .Skip((pageNumber - 1) * pageSize)
                                    .Take(pageSize)
                                    .ToListAsync();

            var viewModels = restaurants.Select(r => new AdminRestaurantListItemViewModel
            {
                Id = r.Id,
                Name = r.Name,
                OwnerDisplayName = r.Owner?.DisplayName ?? r.Owner?.UserName,
                OwnerEmail = r.Owner?.Email,
                FullAddressText = r.Address != null ? $"{r.Address.AddressLine1}, {r.Address.Ward}, {r.Address.District}, {r.Address.City}" : "N/A",
                Status = r.Status,
                CreatedAt = r.CreatedAt,
                UpdatedAt = r.UpdatedAt,
                AverageRating = r.AverageRating,
                ReviewCount = r.ReviewCount,
                ViewDetailsUrl = $"/Restaurants/Details/{r.Id}", // Link xem chi tiết như user thường
                EditRestaurantUrl = $"/AdminRestaurant/Edit/{r.Id}" // Link đến action sửa của Admin
            }).ToList();

            return new PagedResult<AdminRestaurantListItemViewModel>
            {
                Items = viewModels,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalCount = totalCount
            };
        }
        public async Task<GenericResult> ApproveRestaurantAsync(int restaurantId, string adminUserId)
        {
            var restaurant = await _context.Restaurants.FindAsync(restaurantId);
            if (restaurant == null) return new GenericResult { Success = false, ErrorMessage = "Nhà hàng không tồn tại." };

            // (Tùy chọn) Kiểm tra xem adminUserId có hợp lệ và có quyền không
            // var adminUser = await _userManager.FindByIdAsync(adminUserId);
            // if (adminUser == null || !await _userManager.IsInRoleAsync(adminUser, "Admin"))
            // {
            //     return new GenericResult { Success = false, ErrorMessage = "Hành động không được phép." };
            // }

            restaurant.Status = RestaurantStatus.Open;
            restaurant.UpdatedAt = DateTime.UtcNow;
            // Có thể thêm một trường "ApprovedByAdminId" và "ApprovedDate"
            _context.Restaurants.Update(restaurant);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Restaurant ID {RestaurantId} approved by Admin ID {AdminId}", restaurantId, adminUserId);
            return new GenericResult { Success = true };
        }
        public async Task<GenericResult> RejectOrDisableRestaurantAsync(int restaurantId, string? reason, string adminUserId, RestaurantStatus targetStatus = RestaurantStatus.TemporarilyClosed)
        {
            var restaurant = await _context.Restaurants.FindAsync(restaurantId);
            if (restaurant == null) return new GenericResult { Success = false, ErrorMessage = "Nhà hàng không tồn tại." };

            // Kiểm tra quyền admin
            // ...

            if (targetStatus == RestaurantStatus.Open) // Không dùng hàm này để mở
            {
                return new GenericResult { Success = false, ErrorMessage = "Hành động không hợp lệ để mở nhà hàng." };
            }

            restaurant.Status = targetStatus;
            restaurant.UpdatedAt = DateTime.UtcNow;
            // Có thể lưu 'reason' vào một trường mới trong Restaurant hoặc bảng Log riêng
            // restaurant.StatusReason = reason;
            _context.Restaurants.Update(restaurant);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Restaurant ID {RestaurantId} status changed to {Status} by Admin ID {AdminId}. Reason: {Reason}", restaurantId, targetStatus, adminUserId, reason);
            return new GenericResult { Success = true };
        }

        public async Task<GenericResult> UnsuspendRestaurantAsync(int restaurantId, string adminUserId)
        {
            var restaurant = await _context.Restaurants.FindAsync(restaurantId);
            if (restaurant == null) return new GenericResult { Success = false, ErrorMessage = "Nhà hàng không tồn tại." };

            // Kiểm tra quyền admin
            // ...

            if (restaurant.Status == RestaurantStatus.TemporarilyClosed || restaurant.Status == RestaurantStatus.ClosedPermanently /* tùy chính sách */)
            {
                restaurant.Status = RestaurantStatus.Open;
                restaurant.UpdatedAt = DateTime.UtcNow;
                // restaurant.StatusReason = null; // Xóa lý do cũ
                _context.Restaurants.Update(restaurant);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Restaurant ID {RestaurantId} unsuspended by Admin ID {AdminId}", restaurantId, adminUserId);
                return new GenericResult { Success = true };
            }
            return new GenericResult { Success = false, ErrorMessage = "Nhà hàng không ở trạng thái có thể mở lại." };
        }

    }
}
