using System.Collections.Generic;
using PBL3.ViewModel.Menu;

namespace PBL3.ViewModel.Restaurant
{
    public class RestaurantMenuManagementViewModel
    {
        public int RestaurantId { get; set; }
        public string RestaurantName { get; set; }

        // Danh sách các Menu hiện có, sử dụng các ViewModel đã tạo cho trang chi tiết để hiển thị
        public List<MenuViewModel> Menus { get; set; }

        // Các thuộc tính này có thể dùng để truyền dữ liệu cho các modal/form tạo mới
        // mà không cần tải lại toàn bộ trang, hoặc để binding khi form tạo mới được nhúng vào trang.
        // Tạm thời có thể chưa cần ngay nếu bạn dùng các trang riêng hoặc modal riêng biệt cho việc tạo/sửa.
        // public MenuEditViewModel? NewMenuInput { get; set; }
        // public MenuSectionEditViewModel? NewMenuSectionInput { get; set; }
        // public MenuItemEditViewModel? NewMenuItemInput { get; set; }

        public RestaurantMenuManagementViewModel()
        {
            Menus = new List<MenuViewModel>();
        }
    }
}