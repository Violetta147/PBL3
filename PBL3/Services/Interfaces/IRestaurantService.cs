using PBL3.Models; // Cho Restaurant, CuisineType, Tag
using System.Threading.Tasks;
using System.Collections.Generic;
using PBL3.Models.Common;
using PBL3.ViewModel.Restaurant; // Cho PagedResult (nếu bạn đã tạo PagedResult ở đó)
using PBL3.ViewModel.Admin;
using X.PagedList; // Nếu bạn sử dụng X.PagedList cho phân trang

namespace PBL3.Services.Interfaces
{
    public interface IRestaurantService
    {   
        
        /// <summary>
        /// Chuẩn hóa địa chỉ và tọa độ với giá trị mặc định cho Đà Nẵng nếu không được cung cấp
        /// </summary>
        /// <param name="address">Địa chỉ đầu vào, có thể null hoặc rỗng</param>
        /// <param name="latitude">Tọa độ vĩ độ đầu vào, có thể null</param>
        /// <param name="longitude">Tọa độ kinh độ đầu vào, có thể null</param>
        /// <param name="maxDistance">Bán kính tìm kiếm đầu vào, có thể null</param>
        /// <returns>Tuple chứa địa chỉ, tọa độ vĩ độ, kinh độ và bán kính đã chuẩn hóa</returns>
        Task<(string address, double latitude, double longitude, double radiusInKm)> NormalizeLocationParameters(
            string? address, double? latitude = null, double? longitude = null, string? maxDistance = null);
             /// <summary>
        /// Lấy danh sách nhà hàng phân trang dựa trên ID chủ sở hữu.
        /// </summary>
        /// <param name="ownerId">ID của chủ sở hữu nhà hàng.</param>
        /// <param name="page">Số trang hiện tại.</param>
        /// <param name="pageSize">Số lượng bản ghi trên mỗi trang.</param>
        /// <returns>Danh sách nhà hàng phân trang.</returns>
        
        Task<IPagedList<Restaurant>> GetRestaurantByOwnerIdAsync(string ownerId, int page, int pageSize);
         Task<IPagedList<Restaurant>> SearchRestaurantsAdvancedAsync(
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
            int pageNumber = 1,
            int pageSize = 10
        );  
        /// <summary>
        /// Lấy chi tiết thông tin của một nhà hàng dựa trên ID, bao gồm các thông tin liên quan.
        /// </summary>
        Task<Restaurant?> GetRestaurantByIdAsync(int id);

        /// <summary>
        /// Tìm kiếm và lọc nhà hàng, trả về danh sách ViewModel đã được phân trang.
        /// </summary>
        Task<PagedResult<RestaurantListItemViewModel>> SearchRestaurantsAsync(
            string? searchTerm = null,
            IEnumerable<int>? cuisineTypeIds = null,
            IEnumerable<int>? tagIds = null,
            decimal? minPrice = null, // Giá tối thiểu của khoảng giá nhà hàng (MinTypicalPrice)
            decimal? maxPrice = null, // Giá tối đa của khoảng giá nhà hàng (MaxTypicalPrice)
            bool? isOpenNow = null,   // Lọc theo nhà hàng đang mở cửa
            string? sortBy = null,     // Ví dụ: "rating_desc", "name_asc"
            int pageNumber = 1,
            int pageSize = 10
        );

        Task<PagedResult<AdminRestaurantListItemViewModel>> GetAllRestaurantsForAdminAsync(
            string? searchTerm = null,
            RestaurantStatus? statusFilter = null, // Lọc theo trạng thái
            string? ownerSearchTerm = null,        // Tìm theo tên hoặc email chủ sở hữu
            string? sortBy = null,                 // Sắp xếp
            int pageNumber = 1,
            int pageSize = 10
        );
        Task<int> GetRestaurantCountByOwnerIdAsync(string userId);

        Task<GenericResult> ApproveRestaurantAsync(int restaurantId, string adminUserId);

        Task<GenericResult> RejectOrDisableRestaurantAsync(int restaurantId, string? reason, string adminUserId, RestaurantStatus targetStatus = RestaurantStatus.TemporarilyClosed);

        Task<GenericResult> UnsuspendRestaurantAsync(int restaurantId, string adminUserId);
        /// <summary>
        /// Tạo mới một nhà hàng dựa trên thông tin từ ViewModel.
        /// Bao gồm việc tạo Address, OperatingHours, upload ảnh, và liên kết CuisineTypes/Tags.
        /// </summary>
        Task<RestaurantCreationResult> CreateRestaurantAsync(RegisterRestaurantViewModel model, string ownerId);

        /// <summary>
        /// Lấy danh sách các nhà hàng thuộc sở hữu của một người dùng.
        /// </summary>
        Task<IEnumerable<MyRestaurantListItemViewModel>> GetRestaurantsByOwnerIdAsync(string ownerId);
        // Cân nhắc trả về PagedResult<MyRestaurantListItemViewModel> nếu danh sách này có thể dài

        // --- Phương thức lấy dữ liệu cho bộ lọc/dropdowns ---
        /// <summary>
        /// Lấy tất cả các CuisineType.
        /// </summary>
        Task<IEnumerable<CuisineType>> GetCuisineTypesAsync();

        /// <summary>
        /// Lấy tất cả các Tag.
        /// </summary>
        Task<IEnumerable<Tag>> GetTagsAsync();
        Task<RestaurantDetailViewModel?> GetRestaurantDetailViewModelAsync(int id);

        Task<EditRestaurantViewModel?> GetRestaurantForEditAsync(int restaurantId, string requestingUserId);

        Task<GenericResult> UpdateRestaurantAsync(EditRestaurantViewModel model, string requestingUserId);

        Task<(bool IsValid, string? RestaurantName)> ValidateRestaurantOwnershipAsync(int restaurantId, string ownerId);
    }
}

