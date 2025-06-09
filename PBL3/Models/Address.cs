using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public class Address
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Địa chỉ chi tiết không được để trống")]
        [StringLength(300, ErrorMessage = "Địa chỉ không được vượt quá 300 ký tự")]
        public string AddressLine1 { get; set; } // Số nhà, tên đường, thông tin chi tiết

        [Required(ErrorMessage = "Phường/Xã không được để trống")]
        [StringLength(100)]
        public string Ward { get; set; } // Phường/Xã

        [Required(ErrorMessage = "Quận/Huyện không được để trống")]
        [StringLength(100)]
        public string District { get; set; } // Quận/Huyện

        [Required(ErrorMessage = "Tỉnh/Thành phố không được để trống")]
        [StringLength(100)]
        public string City { get; set; } // Tỉnh/Thành phố

        [StringLength(50)]
        public string Country { get; set; } = "Việt Nam";

        [Range(-90, 90, ErrorMessage = "Vĩ độ không hợp lệ.")]
        public double? Latitude { get; set; }

        [Range(-180, 180, ErrorMessage = "Kinh độ không hợp lệ.")]
        public double? Longitude { get; set; }

        // Thuộc tính FullAddress (tính toán, không ánh xạ vào DB nếu không muốn)
        [NotMapped] // Để không tạo cột này trong DB, sẽ tính toán khi cần
        public string FullAddress
        {
            get
            {
                // Ghép chuỗi, có thể tùy chỉnh cách hiển thị
                return $"{AddressLine1}, {Ward}, {District}, {City}{(string.IsNullOrWhiteSpace(Country) || Country == "Việt Nam" ? "" : ", " + Country)}";
            }
        }

        // Foreign Key cho người dùng (nếu địa chỉ này thuộc sổ địa chỉ của người dùng)
        public string UserId { get; set; } // Nullable
        [ForeignKey("UserId")]
        public virtual AppUser User { get; set; }

        // Navigation properties
        public virtual ICollection<Restaurant> Restaurants { get; set; }
        public virtual ICollection<Order> OrdersAsShippingAddress { get; set; }

        public Address()
        {
            Restaurants = new HashSet<Restaurant>();
            OrdersAsShippingAddress = new HashSet<Order>();
        }
    }
}
