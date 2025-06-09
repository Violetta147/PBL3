using PBL3.Models;
using PBL3.ViewModel.Menu;
using PBL3.Models.Common;
using System.Threading.Tasks;
using System.Collections.Generic;
using PBL3.ViewModel.Restaurant;

namespace PBL3.Services.Interfaces
{
    public interface IMenuService
    {
        #region Lấy Dữ Liệu Để Hiển Thị Quản Lý
        /// Lấy toàn bộ cấu trúc menu của một nhà hàng để hiển thị trên trang quản lý.
        Task<RestaurantMenuManagementViewModel?> GetRestaurantMenuForManagementAsync(int restaurantId, string ownerId);
        #endregion

        #region Quản lý Menu
        /// Lấy thông tin Menu để điền vào form chỉnh sửa.
        Task<MenuEditViewModel?> GetMenuForEditAsync(int menuId, string ownerId);

        /// Tạo một Menu mới cho một nhà hàng.
        Task<GenericResult> CreateMenuAsync(MenuEditViewModel model, string ownerId);

        /// Cập nhật thông tin một Menu.
        Task<GenericResult> UpdateMenuAsync(MenuEditViewModel model, string ownerId);

        /// Xóa một Menu (và tất cả các MenuSection, MenuItem thuộc về nó).
        Task<GenericResult> DeleteMenuAsync(int menuId, string ownerId);
        #endregion

        #region Quản lý MenuSection
        /// Lấy thông tin MenuSection để điền vào form chỉnh sửa.
        Task<MenuSectionEditViewModel?> GetMenuSectionForEditAsync(int sectionId, string ownerId);

        /// Tạo một MenuSection mới cho một Menu.
        Task<GenericResult> CreateMenuSectionAsync(MenuSectionEditViewModel model, string ownerId);

        /// Cập nhật thông tin một MenuSection.
        Task<GenericResult> UpdateMenuSectionAsync(MenuSectionEditViewModel model, string ownerId);

        /// Xóa một MenuSection (và tất cả MenuItem thuộc về nó).
        Task<GenericResult> DeleteMenuSectionAsync(int sectionId, string ownerId);
        #endregion

        #region Quản lý MenuItem
        /// Lấy thông tin MenuItem để điền vào form chỉnh sửa, bao gồm cả danh sách AvailableCategories.
        Task<MenuItemEditViewModel?> GetMenuItemForEditAsync(int itemId, string ownerId, int sectionIdForCreate = 0, int restaurantIdForCreate = 0);

        /// Tạo một MenuItem mới cho một MenuSection.
        Task<GenericResult> CreateMenuItemAsync(MenuItemEditViewModel model, string ownerId);

        /// Cập nhật thông tin một MenuItem.
        Task<GenericResult> UpdateMenuItemAsync(MenuItemEditViewModel model, string ownerId);

        /// Xóa một MenuItem (và các MenuItemPhoto, MenuItemCategory liên quan).
        Task<GenericResult> DeleteMenuItemAsync(int itemId, string ownerId);
        #endregion

        #region Phương thức hỗ trợ (Lookup Data)
        /// Lấy danh sách các Category (của món ăn) để hiển thị dưới dạng lựa chọn (checkbox).
        Task<List<SelectableCategoryViewModel>> GetSelectableCategoriesAsync(List<int>? currentlySelectedCategoryIds = null);

        Task<(bool IsValidOwner, string? MenuName, int RestaurantId)> GetMenuInfoForSectionCreationAsync(int menuId, string ownerId);

        Task<int> GetNextMenuSectionDisplayOrderAsync(int menuId, string ownerId);
        #endregion
    }
}
