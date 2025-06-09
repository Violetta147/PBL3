using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public class OrderLine
    {
        public int Id { get; set; }
        public int OrderId { get; set; }
        public virtual Order Order { get; set; }
        public int MenuItemId { get; set; }
        public virtual MenuItem MenuItem { get; set; }

        [Required]
        [StringLength(150)]
        public string MenuItemNameSnapshot { get; set; }

        [Required]
        [Range(1, 100)]
        public int Quantity { get; set; }

        // --- CẬP NHẬT/THÊM LIÊN QUAN ĐẾN PROMOTION TRÊN ITEM ---
        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal OriginalUnitPriceBeforeDiscount { get; set; } // Giá gốc của món trước khi có giảm giá trên item

        [Column(TypeName = "decimal(18,2)")]
        public decimal DiscountAmountOnThisItem { get; set; } = 0; // Số tiền được giảm giá trên dòng này (từ promotion item)

        // UnitPriceSnapshot sẽ là giá SAU KHI trừ DiscountAmountOnThisItem
        // UnitPriceSnapshot = OriginalUnitPriceBeforeDiscount - DiscountAmountOnThisItem
        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal UnitPriceSnapshot { get; set; }

        // TotalPrice vẫn là Quantity * UnitPriceSnapshot
        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal TotalPrice { get; set; }

        // Khóa ngoại đến Promotion đã được áp dụng cho dòng này (nếu có)
        public int? AppliedItemPromotionId { get; set; } // Nullable
        [ForeignKey("AppliedItemPromotionId")]
        public virtual Promotion AppliedItemPromotion { get; set; }
        // ----------------------------------------------------

        [StringLength(255)]
        public string Note { get; set; }
    }
}
