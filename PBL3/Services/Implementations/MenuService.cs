using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PBL3.Data;
using PBL3.Models;
using PBL3.Models.Common;
using PBL3.Services.Interfaces;
using PBL3.ViewModel.Menu;
using PBL3.ViewModel.Restaurant;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PBL3.Extensions;

namespace PBL3.Services.Implementations
{
    public class MenuService : IMenuService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<AppUser> _userManager; // Dùng để lấy thông tin User nếu cần, hoặc chỉ cần ownerId
        private readonly IPhotoService _photoService;       // Cho việc xử lý ảnh MenuItem
        private readonly ILogger<MenuService> _logger;     // Để log lỗi

        public MenuService(
            ApplicationDbContext context,
            UserManager<AppUser> userManager,
            IPhotoService photoService,
            ILogger<MenuService> logger)
        {
            _context = context;
            _userManager = userManager;
            _photoService = photoService;
            _logger = logger;
        }

        #region Lấy Dữ Liệu Để Hiển Thị Quản Lý
        public async Task<RestaurantMenuManagementViewModel?> GetRestaurantMenuForManagementAsync(int restaurantId, string ownerId)
        {
            var restaurant = await _context.Restaurants
                .Include(r => r.Menus.OrderBy(m => m.DisplayOrder)) // Sắp xếp Menu
                    .ThenInclude(m => m.MenuSections.OrderBy(ms => ms.DisplayOrder)) // Sắp xếp MenuSection
                        .ThenInclude(ms => ms.MenuItems.OrderBy(mi => mi.DisplayOrder)) // Sắp xếp MenuItem
                            .ThenInclude(mi => mi.Photos) // MenuItemPhoto
                .Include(r => r.Menus)
                    .ThenInclude(m => m.MenuSections)
                        .ThenInclude(ms => ms.MenuItems)
                            .ThenInclude(mi => mi.MenuItemCategories)
                                .ThenInclude(mc => mc.Category)
                .AsNoTracking() // Chỉ đọc
                .FirstOrDefaultAsync(r => r.Id == restaurantId);

            if (restaurant == null)
            {
                _logger.LogWarning("GetRestaurantMenuForManagementAsync: Restaurant with ID {RestaurantId} not found.", restaurantId);
                return null;
            }

            if (restaurant.OwnerId != ownerId)
            {
                _logger.LogWarning("GetRestaurantMenuForManagementAsync: User {OwnerId} does not own Restaurant {RestaurantId}.", ownerId, restaurantId);
                return null; // Không có quyền
            }

            var viewModel = new RestaurantMenuManagementViewModel
            {
                RestaurantId = restaurant.Id,
                RestaurantName = restaurant.Name,
                Menus = restaurant.Menus.Select(menuEntity => new MenuViewModel
                {
                    Id = menuEntity.Id,
                    Title = menuEntity.Title,
                    Description = menuEntity.Description,
                    IsActive = menuEntity.IsActive,     // Thêm IsActive
                    DisplayOrder = menuEntity.DisplayOrder, // Thêm DisplayOrder
                    MenuSections = menuEntity.MenuSections.Select(sectionEntity => new MenuSectionViewModel
                    {
                        Id = sectionEntity.Id,
                        Title = sectionEntity.Title,
                        Description = sectionEntity.Description,
                        DisplayOrder = sectionEntity.DisplayOrder, // Thêm DisplayOrder
                        MenuItems = sectionEntity.MenuItems.Select(itemEntity => new MenuItemSummaryViewModel
                        {
                            Id = itemEntity.Id,
                            Name = itemEntity.Name,
                            Description = itemEntity.Description,
                            PriceDisplay = $"{itemEntity.Price:N0} VNĐ",
                            MainImageUrl = itemEntity.Photos?.FirstOrDefault(p => p.IsMainImage)?.Url ?? itemEntity.Photos?.FirstOrDefault()?.Url,
                            CategoryNames = itemEntity.MenuItemCategories?.Select(mc => mc.Category.Name).ToList() ?? new List<string>(),
                            IsSignatureDish = itemEntity.IsSignatureDish,
                            IsAvailable = itemEntity.IsAvailable,     // Thêm IsAvailable
                            DisplayOrder = itemEntity.DisplayOrder  // Thêm DisplayOrder
                        }).ToList() // Đã sắp xếp bằng .OrderBy ở Include
                    }).ToList() // Đã sắp xếp bằng .OrderBy ở Include
                }).ToList() // Đã sắp xếp bằng .OrderBy ở Include
            };

            return viewModel;
        }
        #endregion

        #region Phương thức hỗ trợ (Lookup Data)
        public async Task<List<SelectableCategoryViewModel>> GetSelectableCategoriesAsync(List<int>? currentlySelectedCategoryIds = null)
        {
            var allCategories = await _context.Categories
                                        .OrderBy(c => c.Name) // Sắp xếp theo tên
                                        .AsNoTracking()
                                        .ToListAsync();

            return allCategories.Select(c => new SelectableCategoryViewModel
            {
                Id = c.Id,
                Name = c.Name, // Có thể tạo HierarchyName nếu Category có cha-con
                IconUrl = c.IconUrl,
                IsSelected = currentlySelectedCategoryIds?.Contains(c.Id) ?? false
            }).ToList();
        }
        #endregion

        // --- CÁC PHƯƠNG THỨC CRUD CHO MENU, MENUSECTION, MENUITEM SẼ ĐƯỢC THÊM VÀO ĐÂY ---
        // Ví dụ bắt đầu với GetMenuForEditAsync

        #region Quản lý Menu
        public async Task<MenuEditViewModel?> GetMenuForEditAsync(int menuId, string ownerId)
        {
            var menu = await _context.Menus
                                .Include(m => m.Restaurant) // Cần để kiểm tra OwnerId của Restaurant
                                .AsNoTracking()
                                .FirstOrDefaultAsync(m => m.Id == menuId);

            if (menu == null)
            {
                _logger.LogWarning("GetMenuForEditAsync: Menu with ID {MenuId} not found.", menuId);
                return null;
            }

            if (menu.Restaurant?.OwnerId != ownerId) // Kiểm tra null cho Restaurant
            {
                _logger.LogWarning("GetMenuForEditAsync: User {OwnerId} does not own the restaurant of Menu {MenuId}.", ownerId, menuId);
                return null;
            }

            return new MenuEditViewModel
            {
                Id = menu.Id,
                Title = menu.Title,
                Description = menu.Description,
                IsActive = menu.IsActive,
                DisplayOrder = menu.DisplayOrder,
                RestaurantId = menu.RestaurantId,
                RestaurantName = menu.Restaurant?.Name // Lấy tên nhà hàng
            };
        }

        // CreateMenuAsync, UpdateMenuAsync, DeleteMenuAsync sẽ được thêm sau
        #endregion

        // Các phương thức khác sẽ được triển khai dần dần...
        // Để code ngắn gọn cho phản hồi này, tôi sẽ dừng ở đây và chúng ta sẽ triển khai tiếp.
        // Phần còn lại của các phương thức CRUD sẽ theo một khuôn mẫu tương tự:
        // 1. Kiểm tra quyền sở hữu (quan trọng nhất).
        // 2. Tìm entity (nếu là update/delete).
        // 3. Map từ ViewModel sang Entity (cho create/update).
        // 4. Thực hiện thao tác với DbContext (_context.Add, _context.Update, _context.Remove).
        // 5. Xử lý các mối quan hệ (ví dụ: khi tạo MenuItem, phải thêm vào MenuItemCategories, xử lý ảnh).
        // 6. Gọi SaveChangesAsync().
        // 7. Trả về GenericResult.
        // 8. Bọc trong transaction nếu có nhiều thao tác DB.

        // Các phương thức Create, Update, Delete sẽ được chúng ta làm ở các bước tiếp theo.
        // Bây giờ chúng ta sẽ điền nốt các khai báo phương thức còn lại để IMenuService được implement hoàn chỉnh (dù logic bên trong chưa có)

        #region Quản lý Menu
        // GetMenuForEditAsync đã được triển khai ở trên

        public async Task<GenericResult> CreateMenuAsync(MenuEditViewModel model, string ownerId)
        {
            // 1. Kiểm tra xem RestaurantId có tồn tại và thuộc sở hữu của ownerId không
            var restaurant = await _context.Restaurants
                                        .AsNoTracking() // Chỉ cần kiểm tra, không cần track
                                        .FirstOrDefaultAsync(r => r.Id == model.RestaurantId && r.OwnerId == ownerId);

            if (restaurant == null)
            {
                _logger.LogWarning("CreateMenuAsync: User {OwnerId} attempted to create menu for non-existent or unowned restaurant ID {RestaurantId}.", ownerId, model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Nhà hàng không hợp lệ hoặc bạn không có quyền tạo thực đơn cho nhà hàng này." };
            }

            // (Tùy chọn) Kiểm tra tên Menu có trùng trong cùng một Restaurant không nếu bạn muốn
            var existingMenu = await _context.Menus
                                          .AnyAsync(m => m.RestaurantId == model.RestaurantId && m.Title.ToLower() == model.Title.ToLower());
            if (existingMenu)
            {
                return new GenericResult { Success = false, ErrorMessage = $"Thực đơn với tên '{model.Title}' đã tồn tại trong nhà hàng này." };
            }


            var menuEntity = new Menu
            {
                Title = model.Title,
                Description = model.Description,
                IsActive = model.IsActive,
                DisplayOrder = model.DisplayOrder,
                RestaurantId = model.RestaurantId, // Đã được xác thực ở trên
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            try
            {
                _context.Menus.Add(menuEntity);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Menu '{MenuTitle}' (ID: {MenuId}) created successfully for Restaurant ID {RestaurantId} by User ID: {OwnerId}", menuEntity.Title, menuEntity.Id, model.RestaurantId, ownerId);
                // Có thể trả về ID của menu mới tạo nếu cần
                // return new GenericResultWithId { Success = true, Id = menuEntity.Id };
                return new GenericResult { Success = true };
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "DbUpdateException while creating menu '{MenuTitle}' for Restaurant ID {RestaurantId}.", model.Title, model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Lỗi khi lưu thực đơn vào cơ sở dữ liệu." };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while creating menu '{MenuTitle}' for Restaurant ID {RestaurantId}.", model.Title, model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi không mong muốn xảy ra." };
            }
        }

        public async Task<GenericResult> UpdateMenuAsync(MenuEditViewModel model, string ownerId)
        {
            var menuToUpdate = await _context.Menus
                                        .Include(m => m.Restaurant) // Cần để kiểm tra OwnerId
                                        .FirstOrDefaultAsync(m => m.Id == model.Id);

            if (menuToUpdate == null)
            {
                _logger.LogWarning("UpdateMenuAsync: Menu with ID {MenuId} not found.", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy thực đơn để cập nhật." };
            }

            if (menuToUpdate.Restaurant?.OwnerId != ownerId)
            {
                _logger.LogWarning("UpdateMenuAsync: User {OwnerId} attempted to update menu {MenuId} not owned by them.", ownerId, model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền chỉnh sửa thực đơn này." };
            }

            // (Tùy chọn) Kiểm tra tên Menu có trùng trong cùng một Restaurant không (trừ chính nó)
            var existingMenuWithSameName = await _context.Menus
                                          .AnyAsync(m => m.RestaurantId == menuToUpdate.RestaurantId &&
                                                         m.Id != model.Id &&
                                                         m.Title.ToLower() == model.Title.ToLower());
            if (existingMenuWithSameName)
            {
                return new GenericResult { Success = false, ErrorMessage = $"Thực đơn với tên '{model.Title}' đã tồn tại trong nhà hàng này." };
            }

            menuToUpdate.Title = model.Title;
            menuToUpdate.Description = model.Description;
            menuToUpdate.IsActive = model.IsActive;
            menuToUpdate.DisplayOrder = model.DisplayOrder;
            menuToUpdate.UpdatedAt = DateTime.UtcNow;
            // RestaurantId không nên thay đổi khi update Menu

            try
            {
                _context.Menus.Update(menuToUpdate); // Hoặc chỉ cần _context.Entry(menuToUpdate).State = EntityState.Modified; nếu không có thay đổi phức tạp
                await _context.SaveChangesAsync();
                _logger.LogInformation("Menu '{MenuTitle}' (ID: {MenuId}) updated successfully by User ID: {OwnerId}", menuToUpdate.Title, menuToUpdate.Id, ownerId);
                return new GenericResult { Success = true };
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogError(ex, "DbUpdateConcurrencyException while updating menu ID {MenuId}.", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Dữ liệu có thể đã được người khác thay đổi. Vui lòng thử lại." };
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "DbUpdateException while updating menu ID {MenuId}.", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Lỗi khi lưu thay đổi vào cơ sở dữ liệu." };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while updating menu ID {MenuId}.", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi không mong muốn xảy ra." };
            }
        }
        public async Task<GenericResult> DeleteMenuAsync(int menuId, string ownerId)
        {
            var menuToDelete = await _context.Menus
                                        .Include(m => m.Restaurant)
                                        .FirstOrDefaultAsync(m => m.Id == menuId);

            if (menuToDelete == null)
            {
                _logger.LogWarning("DeleteMenuAsync: Menu with ID {MenuId} not found.", menuId);
                return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy thực đơn để xóa." };
            }

            if (menuToDelete.Restaurant?.OwnerId != ownerId)
            {
                _logger.LogWarning("DeleteMenuAsync: User {OwnerId} attempted to delete menu {MenuId} not owned by them.", ownerId, menuId);
                return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền xóa thực đơn này." };
            }

            // Với cấu hình hiện tại (MenuItem.MenuSectionId OnDelete SetNull,
            // và Menu.MenuSections OnDelete Cascade):
            // 1. Xóa Menu sẽ cascade xóa MenuSections.
            // 2. Xóa MenuSections sẽ set MenuSectionId = null cho các MenuItems liên quan.
            // 3. MenuItems và ảnh của chúng (MenuItemPhoto) sẽ không bị xóa.

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                _context.Menus.Remove(menuToDelete);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("Menu (ID: {MenuId}) deleted successfully by User ID: {OwnerId}. Related MenuItems have their MenuSectionId set to null.", menuId, ownerId);
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Exception while deleting menu ID {MenuId}.", menuId);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi xảy ra khi xóa thực đơn." };
            }
        }
        #endregion

        #region Quản lý MenuSection
        public async Task<MenuSectionEditViewModel?> GetMenuSectionForEditAsync(int sectionId, string ownerId)
        {
            var section = await _context.MenuSections
                                    .Include(ms => ms.Menu) // Cần Menu để lấy MenuName và RestaurantId
                                        .ThenInclude(m => m.Restaurant) // Cần Restaurant để kiểm tra OwnerId
                                    .AsNoTracking()
                                    .FirstOrDefaultAsync(ms => ms.Id == sectionId);

            if (section == null)
            {
                _logger.LogWarning("GetMenuSectionForEditAsync: MenuSection with ID {SectionId} not found.", sectionId);
                return null;
            }

            // Kiểm tra quyền sở hữu thông qua Restaurant của Menu
            if (section.Menu?.Restaurant?.OwnerId != ownerId)
            {
                _logger.LogWarning("GetMenuSectionForEditAsync: User {OwnerId} does not own the restaurant for MenuSection {SectionId}.", ownerId, sectionId);
                return null;
            }

            return new MenuSectionEditViewModel
            {
                Id = section.Id,
                Title = section.Title,
                Description = section.Description,
                DisplayOrder = section.DisplayOrder,
                MenuId = section.MenuId,
                MenuName = section.Menu?.Title, // Lấy tên Menu
                RestaurantId = section.Menu.RestaurantId // Lấy RestaurantId từ Menu cha
            };
        }

        public async Task<GenericResult> CreateMenuSectionAsync(MenuSectionEditViewModel model, string ownerId)
        {
            // 1. Kiểm tra xem MenuId có tồn tại và thuộc sở hữu của ownerId không
            var parentMenu = await _context.Menus
                                        .Include(m => m.Restaurant)
                                        .AsNoTracking()
                                        .FirstOrDefaultAsync(m => m.Id == model.MenuId && m.Restaurant.OwnerId == ownerId);

            if (parentMenu == null)
            {
                _logger.LogWarning("CreateMenuSectionAsync: User {OwnerId} attempted to create section for non-existent, unowned, or mismatched Restaurant (MenuId: {MenuId}, Model.RestaurantId: {ModelRestaurantId}).",
                                   ownerId, model.MenuId, model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Thực đơn không hợp lệ hoặc bạn không có quyền thêm mục vào thực đơn này." };
            }

            // Đảm bảo RestaurantId trong model (nếu có) khớp với RestaurantId của parentMenu
            if (model.RestaurantId != parentMenu.RestaurantId)
            {
                _logger.LogWarning("CreateMenuSectionAsync: Mismatched RestaurantId. Menu's RestaurantId: {MenuRestaurantId}, Model's RestaurantId: {ModelRestaurantId}",
                                  parentMenu.RestaurantId, model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Thông tin nhà hàng không khớp với thực đơn." };
            }

            // (Tùy chọn) Kiểm tra tên MenuSection có trùng trong cùng một Menu không
            var existingSection = await _context.MenuSections
                                          .AnyAsync(ms => ms.MenuId == model.MenuId && ms.Title.ToLower() == model.Title.ToLower());
            if (existingSection)
            {
                return new GenericResult { Success = false, ErrorMessage = $"Mục với tên '{model.Title}' đã tồn tại trong thực đơn này." };
            }

            var sectionEntity = new MenuSection
            {
                Title = model.Title,
                Description = model.Description,
                DisplayOrder = model.DisplayOrder,
                MenuId = model.MenuId, // Đã được xác thực
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            try
            {
                _context.MenuSections.Add(sectionEntity);
                await _context.SaveChangesAsync();
                _logger.LogInformation("MenuSection '{SectionTitle}' (ID: {SectionId}) created successfully for Menu ID {MenuId} by User ID: {OwnerId}",
                                       sectionEntity.Title, sectionEntity.Id, model.MenuId, ownerId);
                return new GenericResult { Success = true /* , Id = sectionEntity.Id */ };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while creating menu section '{SectionTitle}' for Menu ID {MenuId}.", model.Title, model.MenuId);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi xảy ra khi tạo mục thực đơn." };
            }
        }

        public async Task<GenericResult> UpdateMenuSectionAsync(MenuSectionEditViewModel model, string ownerId)
        {
            var sectionToUpdate = await _context.MenuSections
                                            .Include(ms => ms.Menu)
                                                .ThenInclude(m => m.Restaurant)
                                            .FirstOrDefaultAsync(ms => ms.Id == model.Id);

            if (sectionToUpdate == null)
            {
                _logger.LogWarning("UpdateMenuSectionAsync: MenuSection with ID {SectionId} not found.", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy mục thực đơn để cập nhật." };
            }

            if (sectionToUpdate.Menu?.Restaurant?.OwnerId != ownerId || sectionToUpdate.Menu.RestaurantId != model.RestaurantId)
            {
                _logger.LogWarning("UpdateMenuSectionAsync: User {OwnerId} attempted to update section {SectionId} not owned by them or mismatched restaurant.", ownerId, model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền chỉnh sửa mục thực đơn này hoặc thông tin nhà hàng không khớp." };
            }

            // (Tùy chọn) Kiểm tra trùng tên
            var existingSectionWithSameName = await _context.MenuSections
                                          .AnyAsync(ms => ms.MenuId == sectionToUpdate.MenuId &&
                                                         ms.Id != model.Id &&
                                                         ms.Title.ToLower() == model.Title.ToLower());
            if (existingSectionWithSameName) {
                return new GenericResult { Success = false, ErrorMessage = $"Mục với tên '{model.Title}' đã tồn tại trong nhà hàng này." };
            }


            sectionToUpdate.Title = model.Title;
            sectionToUpdate.Description = model.Description;
            sectionToUpdate.DisplayOrder = model.DisplayOrder;
            sectionToUpdate.UpdatedAt = DateTime.UtcNow;
            // MenuId và RestaurantId không nên thay đổi khi update MenuSection

            try
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("MenuSection '{SectionTitle}' (ID: {SectionId}) updated successfully by User ID: {OwnerId}", sectionToUpdate.Title, sectionToUpdate.Id, ownerId);
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while updating menu section ID {SectionId}.", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi xảy ra khi cập nhật mục thực đơn." };
            }
        }

        public async Task<GenericResult> DeleteMenuSectionAsync(int sectionId, string ownerId)
        {
            var sectionToDelete = await _context.MenuSections
                                            .Include(ms => ms.Menu)
                                                .ThenInclude(m => m.Restaurant)
                                            .FirstOrDefaultAsync(ms => ms.Id == sectionId);

            if (sectionToDelete == null)
            {
                _logger.LogWarning("DeleteMenuSectionAsync: MenuSection with ID {SectionId} not found.", sectionId);
                return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy mục thực đơn để xóa." };
            }

            if (sectionToDelete.Menu?.Restaurant?.OwnerId != ownerId)
            {
                _logger.LogWarning("DeleteMenuSectionAsync: User {OwnerId} attempted to delete section {SectionId} not owned by them.", ownerId, sectionId);
                return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền xóa mục thực đơn này." };
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                _context.MenuSections.Remove(sectionToDelete);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("MenuSection (ID: {SectionId}) deleted successfully by User ID: {OwnerId}. Related MenuItems have their MenuSectionId set to null.", sectionId, ownerId);
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Exception while deleting menu section ID {SectionId}.", sectionId);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi xảy ra khi xóa mục thực đơn." };
            }
        }
        #endregion

        #region Quản lý MenuItem
        public async Task<MenuItemEditViewModel?> GetMenuItemForEditAsync(int itemId, string ownerId, int sectionIdForCreate = 0, int restaurantIdForCreate = 0)
        {
            MenuItemEditViewModel viewModel;
            List<int> selectedCategoryIds = new List<int>();
            string? restaurantName = null;
            string? menuSectionName = null;
            int validRestaurantId = 0;
            int validMenuSectionId = 0;

            if (itemId > 0) // Chế độ Sửa
            {
                var menuItemEntity = await _context.MenuItems
                                            .Include(mi => mi.MenuSection)
                                                .ThenInclude(ms => ms.Menu)
                                                    .ThenInclude(m => m.Restaurant)
                                            .Include(mi => mi.Photos)
                                            .Include(mi => mi.MenuItemCategories)
                                            .AsNoTracking()
                                            .FirstOrDefaultAsync(mi => mi.Id == itemId);

                if (menuItemEntity == null)
                {
                    _logger.LogWarning("GetMenuItemForEditAsync (Edit): MenuItem with ID {ItemId} not found.", itemId);
                    return null;
                }

                if (menuItemEntity.MenuSection?.Menu?.Restaurant?.OwnerId != ownerId)
                {
                    _logger.LogWarning("GetMenuItemForEditAsync (Edit): User {OwnerId} does not own restaurant for MenuItem {ItemId}.", ownerId, itemId);
                    return null;
                }

                selectedCategoryIds = menuItemEntity.MenuItemCategories.Select(mc => mc.CategoryId).ToList();
                viewModel = new MenuItemEditViewModel
                {
                    Id = menuItemEntity.Id,
                    Name = menuItemEntity.Name,
                    Description = menuItemEntity.Description,
                    Price = menuItemEntity.Price,
                    IsAvailable = menuItemEntity.IsAvailable,
                    IsSignatureDish = menuItemEntity.IsSignatureDish,
                    DisplayOrder = menuItemEntity.DisplayOrder,
                    MenuSectionId = menuItemEntity.MenuSectionId ?? 0, // Nên là Required, không thể null nếu item tồn tại
                    RestaurantId = menuItemEntity.RestaurantId,
                    CurrentMainImageUrl = menuItemEntity.Photos?.FirstOrDefault(p => p.IsMainImage)?.Url ?? menuItemEntity.Photos?.FirstOrDefault()?.Url,
                    CurrentMainImagePublicId = menuItemEntity.Photos?.FirstOrDefault(p => p.IsMainImage)?.CloudinaryPublicId ?? menuItemEntity.Photos?.FirstOrDefault()?.CloudinaryPublicId,
                };
                restaurantName = menuItemEntity.MenuSection?.Menu?.Restaurant?.Name;
                menuSectionName = menuItemEntity.MenuSection?.Title;
                validRestaurantId = menuItemEntity.RestaurantId;
                validMenuSectionId = menuItemEntity.MenuSectionId ?? 0;
            }
            else // Chế độ Tạo mới (itemId = 0)
            {
                if (sectionIdForCreate <= 0 || restaurantIdForCreate <= 0)
                {
                    _logger.LogWarning("GetMenuItemForEditAsync (Create): Invalid sectionIdForCreate {SectionId} or restaurantIdForCreate {RestaurantId}.", sectionIdForCreate, restaurantIdForCreate);
                    return null; // Cần sectionId và restaurantId hợp lệ
                }

                var parentSection = await _context.MenuSections
                                            .Include(ms => ms.Menu)
                                                .ThenInclude(m => m.Restaurant)
                                            .AsNoTracking()
                                            .FirstOrDefaultAsync(ms => ms.Id == sectionIdForCreate &&
                                                                      ms.Menu.RestaurantId == restaurantIdForCreate &&
                                                                      ms.Menu.Restaurant.OwnerId == ownerId);
                if (parentSection == null)
                {
                    _logger.LogWarning("GetMenuItemForEditAsync (Create): User {OwnerId} - Invalid parent MenuSection or Restaurant.", ownerId);
                    return null;
                }

                viewModel = new MenuItemEditViewModel
                {
                    Id = 0,
                    MenuSectionId = sectionIdForCreate,
                    RestaurantId = restaurantIdForCreate,
                    IsAvailable = true, // Mặc định
                    DisplayOrder = (await _context.MenuItems.Where(mi => mi.MenuSectionId == sectionIdForCreate).MaxAsync(mi => (int?)mi.DisplayOrder) ?? -1) + 1
                };
                restaurantName = parentSection.Menu.Restaurant.Name;
                menuSectionName = parentSection.Title;
                validRestaurantId = restaurantIdForCreate;
                validMenuSectionId = sectionIdForCreate;
            }

            viewModel.RestaurantName = restaurantName;
            viewModel.MenuSectionName = menuSectionName;
            viewModel.AvailableCategories = await GetSelectableCategoriesAsync(selectedCategoryIds);

            return viewModel;
        }

        public async Task<GenericResult> CreateMenuItemAsync(MenuItemEditViewModel model, string ownerId)
        {
            // 1. Kiểm tra MenuSectionId có tồn tại và thuộc nhà hàng của ownerId không
            var parentSection = await _context.MenuSections
                                        .Include(ms => ms.Menu)
                                            .ThenInclude(m => m.Restaurant)
                                        .AsNoTracking()
                                        .FirstOrDefaultAsync(ms => ms.Id == model.MenuSectionId &&
                                                                  ms.Menu.RestaurantId == model.RestaurantId &&
                                                                  ms.Menu.Restaurant.OwnerId == ownerId);
            if (parentSection == null)
            {
                _logger.LogWarning("CreateMenuItem: User {OwnerId} - Invalid parent MenuSection {MenuSectionId} or Restaurant {RestaurantId}.", ownerId, model.MenuSectionId, model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Mục thực đơn không hợp lệ hoặc bạn không có quyền." };
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var menuItemEntity = new MenuItem
                {
                    Name = model.Name,
                    Description = model.Description,
                    Price = model.Price,
                    IsAvailable = model.IsAvailable,
                    IsSignatureDish = model.IsSignatureDish,
                    DisplayOrder = model.DisplayOrder,
                    MenuSectionId = model.MenuSectionId,
                    RestaurantId = model.RestaurantId, // Lấy từ model, đã được validate qua parentSection
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    Photos = new List<MenuItemPhoto>(),
                    MenuItemCategories = new List<MenuItemCategory>()
                };
                _context.MenuItems.Add(menuItemEntity);
                await _context.SaveChangesAsync(); // Lưu MenuItem để lấy Id

                // Xử lý upload ảnh
                if (model.NewMainImageFile != null && model.NewMainImageFile.Length > 0)
                {
                    string imageFolder = $"restaurants/{model.RestaurantId}/menu_items/{menuItemEntity.Id}";
                    var uploadResult = await _photoService.UploadPhotoAsync(model.NewMainImageFile, imageFolder);

                    if (uploadResult.Success && !string.IsNullOrEmpty(uploadResult.Url) && !string.IsNullOrEmpty(uploadResult.PublicId))
                    {
                        var menuItemPhoto = new MenuItemPhoto
                        {
                            MenuItemId = menuItemEntity.Id, // Gán Id
                            Url = uploadResult.Url,
                            CloudinaryPublicId = uploadResult.PublicId,
                            IsMainImage = true,
                            UploadedDate = DateTime.UtcNow
                        };
                        _context.MenuItemPhotos.Add(menuItemPhoto);
                    }
                    else
                    {
                        await transaction.RollbackAsync();
                        return new GenericResult { Success = false, ErrorMessage = $"Lỗi tải ảnh: {uploadResult.ErrorMessage}" };
                    }
                }

                // Xử lý MenuItemCategories
                if (model.SelectedCategoryIds != null && model.SelectedCategoryIds.Any())
                {
                    foreach (var categoryId in model.SelectedCategoryIds)
                    {
                        if (await _context.Categories.AnyAsync(c => c.Id == categoryId))
                        {
                            _context.MenuItemCategories.Add(new MenuItemCategory { MenuItemId = menuItemEntity.Id, CategoryId = categoryId });
                        }
                    }
                }

                await _context.SaveChangesAsync(); // Lưu MenuItemPhoto và MenuItemCategories
                await transaction.CommitAsync();
                return new GenericResult { Success = true /*, Id = menuItemEntity.Id */ };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Exception creating MenuItem '{ItemName}'.", model.Name);
                return new GenericResult { Success = false, ErrorMessage = "Lỗi hệ thống khi tạo món ăn." };
            }
        }

        public async Task<GenericResult> UpdateMenuItemAsync(MenuItemEditViewModel model, string ownerId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var itemToUpdate = await _context.MenuItems
                    .Include(mi => mi.MenuSection.Menu.Restaurant)
                    .Include(mi => mi.Photos)
                    .Include(mi => mi.MenuItemCategories)
                    .FirstOrDefaultAsync(mi => mi.Id == model.Id);

                if (itemToUpdate == null)
                {
                    await transaction.RollbackAsync();
                    return new GenericResult { Success = false, ErrorMessage = "Món ăn không tồn tại." };
                }
                if (itemToUpdate.MenuSection?.Menu?.Restaurant?.OwnerId != ownerId || itemToUpdate.RestaurantId != model.RestaurantId)
                {
                    await transaction.RollbackAsync();
                    return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền sửa món ăn này." };
                }

                // Cập nhật thông tin cơ bản
                itemToUpdate.Name = model.Name;
                itemToUpdate.Description = model.Description;
                itemToUpdate.Price = model.Price;
                itemToUpdate.IsAvailable = model.IsAvailable;
                itemToUpdate.IsSignatureDish = model.IsSignatureDish;
                itemToUpdate.DisplayOrder = model.DisplayOrder;
                itemToUpdate.UpdatedAt = DateTime.UtcNow;

                // Xử lý ảnh
                if (model.NewMainImageFile != null && model.NewMainImageFile.Length > 0)
                {
                    // Xóa ảnh chính cũ (nếu có) trên Cloudinary và DB
                    var currentMainPhoto = itemToUpdate.Photos.FirstOrDefault(p => p.IsMainImage);
                    if (currentMainPhoto != null)
                    {
                        if (!string.IsNullOrEmpty(currentMainPhoto.CloudinaryPublicId))
                        {
                            await _photoService.DeletePhotoAsync(currentMainPhoto.CloudinaryPublicId);
                        }
                        _context.MenuItemPhotos.Remove(currentMainPhoto);
                    }

                    // Upload ảnh mới
                    string imageFolder = $"restaurants/{itemToUpdate.RestaurantId}/menu_items/{itemToUpdate.Id}";
                    var uploadResult = await _photoService.UploadPhotoAsync(model.NewMainImageFile, imageFolder);
                    if (uploadResult.Success && !string.IsNullOrEmpty(uploadResult.Url) && !string.IsNullOrEmpty(uploadResult.PublicId))
                    {
                        itemToUpdate.Photos.Add(new MenuItemPhoto // Thêm vào collection để EF theo dõi
                        {
                            MenuItem = itemToUpdate, // Hoặc MenuItemId = itemToUpdate.Id
                            Url = uploadResult.Url,
                            CloudinaryPublicId = uploadResult.PublicId,
                            IsMainImage = true,
                            UploadedDate = DateTime.UtcNow
                        });
                    }
                    else
                    {
                        await transaction.RollbackAsync();
                        return new GenericResult { Success = false, ErrorMessage = $"Lỗi tải ảnh: {uploadResult.ErrorMessage}" };
                    }
                }
                else if (string.IsNullOrEmpty(model.CurrentMainImageUrl) && !string.IsNullOrEmpty(itemToUpdate.Photos.FirstOrDefault(p => p.IsMainImage)?.Url))
                {
                    // Trường hợp người dùng xóa ảnh hiện tại mà không upload ảnh mới
                    var currentMainPhoto = itemToUpdate.Photos.FirstOrDefault(p => p.IsMainImage);
                    if (currentMainPhoto != null)
                    {
                        if (!string.IsNullOrEmpty(currentMainPhoto.CloudinaryPublicId))
                        {
                            await _photoService.DeletePhotoAsync(currentMainPhoto.CloudinaryPublicId);
                        }
                        _context.MenuItemPhotos.Remove(currentMainPhoto);
                    }
                }


                // Cập nhật MenuItemCategories (Xóa cũ, thêm mới)
                _context.MenuItemCategories.RemoveRange(itemToUpdate.MenuItemCategories); // Xóa các liên kết cũ
                                                                                          // itemToUpdate.MenuItemCategories.Clear(); // Clear collection trên entity

                if (model.SelectedCategoryIds != null && model.SelectedCategoryIds.Any())
                {
                    foreach (var categoryId in model.SelectedCategoryIds)
                    {
                        if (await _context.Categories.AnyAsync(c => c.Id == categoryId))
                        {
                            _context.MenuItemCategories.Add(new MenuItemCategory { MenuItemId = itemToUpdate.Id, CategoryId = categoryId });
                        }
                    }
                }

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Exception updating MenuItem ID {ItemId}.", model.Id);
                return new GenericResult { Success = false, ErrorMessage = "Lỗi hệ thống khi cập nhật món ăn." };
            }
        }

        public async Task<GenericResult> DeleteMenuItemAsync(int itemId, string ownerId)
        {
            var itemToDelete = await _context.MenuItems
                .Include(mi => mi.MenuSection.Menu.Restaurant)
                .Include(mi => mi.Photos) // Để xóa ảnh trên Cloudinary
                                          // MenuItemCategories sẽ bị xóa theo Cascade nếu cấu hình đúng
                .FirstOrDefaultAsync(mi => mi.Id == itemId);

            if (itemToDelete == null)
            {
                return new GenericResult { Success = false, ErrorMessage = "Món ăn không tồn tại." };
            }
            if (itemToDelete.MenuSection?.Menu?.Restaurant?.OwnerId != ownerId)
            {
                return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền xóa món ăn này." };
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // Xóa ảnh trên Cloudinary
                if (itemToDelete.Photos.Any())
                {
                    foreach (var photo in itemToDelete.Photos.ToList()) // ToList() để tránh lỗi khi modify collection
                    {
                        if (!string.IsNullOrEmpty(photo.CloudinaryPublicId))
                        {
                            await _photoService.DeletePhotoAsync(photo.CloudinaryPublicId);
                        }
                        // Không cần _context.MenuItemPhotos.Remove(photo) vì Cascade Delete từ MenuItem
                    }
                }

                _context.MenuItems.Remove(itemToDelete); // EF Core sẽ Cascade Delete MenuItemPhotos và MenuItemCategories
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Exception deleting MenuItem ID {ItemId}.", itemId);
                return new GenericResult { Success = false, ErrorMessage = "Lỗi hệ thống khi xóa món ăn." };
            }
        }
        #endregion

        public async Task<(bool IsValidOwner, string? MenuName, int RestaurantId)> GetMenuInfoForSectionCreationAsync(int menuId, string ownerId)
        {
            var menu = await _context.Menus
                                    .Include(m => m.Restaurant) // Cần Restaurant để kiểm tra OwnerId
                                    .AsNoTracking()
                                    .Where(m => m.Id == menuId)
                                    .Select(m => new { m.Title, m.RestaurantId, m.Restaurant.OwnerId }) // Chỉ lấy các trường cần thiết
                                    .FirstOrDefaultAsync();

            if (menu == null)
            {
                _logger.LogWarning("GetMenuInfoForSectionCreationAsync: Menu with ID {MenuId} not found.", menuId);
                return (false, null, 0);
            }

            if (menu.OwnerId != ownerId)
            {
                _logger.LogWarning("GetMenuInfoForSectionCreationAsync: User {RequestingOwnerId} does not own the restaurant of Menu {MenuId} (Actual Owner: {ActualOwnerId}).", ownerId, menuId, menu.OwnerId);
                return (false, null, 0);
            }

            return (true, menu.Title, menu.RestaurantId);
        }

        public async Task<int> GetNextMenuSectionDisplayOrderAsync(int menuId, string ownerId)
        {
            // Kiểm tra quyền sở hữu menuId với ownerId trước
            var menu = await _context.Menus
                                .Include(m => m.Restaurant)
                                .AsNoTracking()
                                .FirstOrDefaultAsync(m => m.Id == menuId && m.Restaurant.OwnerId == ownerId);
            if (menu == null)
            {
                // Ném lỗi hoặc trả về giá trị mặc định không hợp lệ để Controller xử lý
                throw new UnauthorizedAccessException("User does not own this menu or menu not found.");
            }

            var maxDisplayOrder = await _context.MenuSections
                                            .Where(ms => ms.MenuId == menuId)
                                            .MaxAsync(ms => (int?)ms.DisplayOrder); // (int?) để MaxAsync hoạt động với collection rỗng
            return (maxDisplayOrder ?? -1) + 1;
        }
    }
}