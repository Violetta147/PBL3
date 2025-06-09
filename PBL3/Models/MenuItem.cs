using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class MenuItem
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Tên món ăn không được để trống.")]
        [StringLength(150, MinimumLength = 2, ErrorMessage = "Tên món ăn phải từ 2 đến 150 ký tự.")]
        public string Name { get; set; }

        [StringLength(1000, ErrorMessage = "Mô tả món ăn không được vượt quá 1000 ký tự.")]
        public string Description { get; set; }

        [Required(ErrorMessage = "Giá món ăn không được để trống.")]
        [Range(0, double.MaxValue, ErrorMessage = "Giá món ăn phải là một số không âm.")]
        public decimal Price { get; set; }

        public bool IsAvailable { get; set; } = true;
        public bool IsSignatureDish { get; set; } = false;
        [Range(0, int.MaxValue, ErrorMessage = "Thứ tự hiển thị phải là số không âm.")]
        public int DisplayOrder { get; set; } // Thứ tự trong một section (nếu có)

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Foreign Key đến Restaurant (Món ăn luôn thuộc về một nhà hàng)
        [Required(ErrorMessage = "Món ăn phải thuộc về một nhà hàng.")]
        public int RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        // Foreign Key đến MenuSection - LÀM CHO NULLABLE
        public int? MenuSectionId { get; set; } // Có thể null
        [ForeignKey("MenuSectionId")]
        public virtual MenuSection MenuSection { get; set; }

        public virtual ICollection<MenuItemPhoto> Photos { get; set; }
        public virtual ICollection<MenuItemCategory> MenuItemCategories { get; set; }
        public virtual ICollection<PromotionApplicableItem> PromotionsAppliedToThisItem { get; set; }
        public MenuItem()
        {
            Photos = new HashSet<MenuItemPhoto>();
            MenuItemCategories = new HashSet<MenuItemCategory>();
            PromotionsAppliedToThisItem = new HashSet<PromotionApplicableItem>();
            IsAvailable = true;
            CreatedAt = System.DateTime.UtcNow; // Sử dụng System.DateTime để rõ ràng hơn
            UpdatedAt = System.DateTime.UtcNow;
        }
    }
}
