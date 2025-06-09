using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace PBL3.Models
{
    //public enum PriceRange
    //{
    //    [Display(Name = "Rẻ")]
    //    Cheap,
    //    [Display(Name = "Vừa phải")]
    //    Moderate,
    //    [Display(Name = "Đắt")]
    //    Expensive,
    //    [Display(Name = "Rất đắt")]
    //    VeryExpensive
    //}

    public enum RestaurantStatus
    {
        [Display(Name = "Đang mở cửa")]
        Open,
        [Display(Name = "Tạm đóng cửa")]
        TemporarilyClosed,
        [Display(Name = "Đóng cửa vĩnh viễn")]
        ClosedPermanently
    }

    public class Restaurant
    {
        public int Id { get; set; } // Hoặc Guid Id { get; set; }

        [Required(ErrorMessage = "Tên nhà hàng không được để trống.")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Tên nhà hàng phải từ 3 đến 200 ký tự.")]
        public string Name { get; set; }

        [StringLength(2000, ErrorMessage = "Mô tả không được vượt quá 2000 ký tự.")]
        public string Description { get; set; }

        [Required(ErrorMessage = "Vui lòng cung cấp thông tin địa chỉ cho nhà hàng.")]
        public int AddressId { get; set; }
        [ForeignKey("AddressId")]
        public virtual Address Address { get; set; }

        [Phone(ErrorMessage = "Số điện thoại không hợp lệ.")]
        [StringLength(20)]
        public string PhoneNumber { get; set; }

        [Url(ErrorMessage = "Địa chỉ website không hợp lệ.")]
        [StringLength(200)]
        public string? Website { get; set; }

        // --- THAY THẾ PriceRange bằng MinTypicalPrice và MaxTypicalPrice ---
        [Display(Name = "Giá thấp nhất (ước tính)")]
        [Column(TypeName = "decimal(18,0)")] // Có thể không cần phần thập phân cho giá ước tính này
        [Range(0, double.MaxValue, ErrorMessage = "Giá trị không hợp lệ.")]
        public decimal? MinTypicalPrice { get; set; } // Giá ước tính cho một người/một bữa ăn

        [Display(Name = "Giá cao nhất (ước tính)")]
        [Column(TypeName = "decimal(18,0)")]
        [Range(0, double.MaxValue, ErrorMessage = "Giá trị không hợp lệ.")]
        public decimal? MaxTypicalPrice { get; set; } // Giá ước tính cho một người/một bữa ăn

        // Các trường này sẽ được cập nhật bởi logic nghiệp vụ khi có review mới hoặc review bị xóa/thay đổi
        [Display(Name = "Đánh giá trung bình")]
        public double AverageRating { get; set; } = 0; // Giá trị mặc định là 0

        [Display(Name = "Số lượt đánh giá")]
        public int ReviewCount { get; set; } = 0;   // Giá trị mặc định là 0

        [StringLength(500, ErrorMessage = "Đường dẫn ảnh đại diện không được vượt quá 500 ký tự.")]
        public string? MainImageUrl { get; set; } // Ảnh đại diện chính (tùy chọn)
        [Required]
        public RestaurantStatus Status { get; set; } = RestaurantStatus.Open;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Foreign Key cho người sở hữu/quản lý (nếu có)
        public string OwnerId { get; set; } // Kiểu dữ liệu của khóa chính trong IdentityUser (thường là string)
        [ForeignKey("OwnerId")]
        public virtual AppUser Owner { get; set; } // Cần using Microsoft.AspNetCore.Identity; và ApplicationUser là class user của bạn

        // Navigation Properties
        public virtual ICollection<Promotion> Promotions { get; set; }
        public virtual ICollection<Review> Reviews { get; set; }
        public virtual ICollection<RestaurantPhoto> Photos { get; set; }
        public virtual ICollection<RestaurantCuisine> RestaurantCuisines { get; set; }
        public virtual ICollection<RestaurantTag> RestaurantTags { get; set; }
        public virtual ICollection<Menu> Menus { get; set; } // Các menu của nhà hàng
        public virtual ICollection<MenuItem> MenuItems { get; set; }
        public virtual ICollection<OperatingHour> OperatingHours { get; set; }

        public Restaurant()
        {
            Reviews = new HashSet<Review>();
            Photos = new HashSet<RestaurantPhoto>();
            Menus = new HashSet<Menu>();
            RestaurantCuisines = new HashSet<RestaurantCuisine>();
            RestaurantTags = new HashSet<RestaurantTag>();
            MenuItems = new HashSet<MenuItem>();
            Promotions = new HashSet<Promotion>();
            OperatingHours = new HashSet<OperatingHour>();
            Status = RestaurantStatus.Open; // Đảm bảo trạng thái mặc định
        }

        // Thuộc tính [NotMapped] để hiển thị khoảng giá dưới dạng text (tùy chọn)
        [NotMapped]
        public string PriceRangeText
        {
            get
            {
                if (MinTypicalPrice.HasValue && MaxTypicalPrice.HasValue)
                {
                    if (MinTypicalPrice == MaxTypicalPrice)
                        return $"{MinTypicalPrice:N0} VNĐ";
                    return $"{MinTypicalPrice:N0} - {MaxTypicalPrice:N0} VNĐ";
                }
                if (MinTypicalPrice.HasValue)
                    return $"Từ {MinTypicalPrice:N0} VNĐ";
                if (MaxTypicalPrice.HasValue)
                    return $"Đến {MaxTypicalPrice:N0} VNĐ";
                return "Chưa cập nhật";
            }
        }
    }
}
