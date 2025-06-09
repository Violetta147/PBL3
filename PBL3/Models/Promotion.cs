using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class Promotion
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Tên chương trình khuyến mãi không được để trống.")]
        [StringLength(150, MinimumLength = 3, ErrorMessage = "Tên chương trình phải từ 3 đến 150 ký tự.")]
        public string Name { get; set; }

        [StringLength(500)]
        public string Description { get; set; }

        [Required]
        public PromotionType Type { get; set; }

        [Required(ErrorMessage = "Giá trị giảm giá không được để trống.")]
        [Column(TypeName = "decimal(18,2)")]
        // Logic validation cho giá trị này (ví dụ: 1-100 cho %, >=0 cho số tiền)
        // sẽ được xử lý ở tầng Service/ViewModel, không đặt [Range] trực tiếp ở đây
        // để giữ model linh hoạt cho các PromotionType khác nhau.
        public decimal DiscountValue { get; set; }

        [Column(TypeName = "decimal(18,2)")]
        public decimal? MaxDiscountAmountForPercentage { get; set; }

        [StringLength(50)]
        // Unique index sẽ được cấu hình bằng Fluent API
        public string CouponCode { get; set; } // Nullable nếu không phải loại dùng mã

        [Required]
        public DateTime StartDate { get; set; } = DateTime.UtcNow;
        public DateTime? EndDate { get; set; }
        public bool IsActive { get; set; } = true;

        [Column(TypeName = "decimal(18,2)")]
        public decimal? MinOrderValue { get; set; } // Giá trị đơn hàng tối thiểu để áp dụng

        // --- GIỚI HẠN SỬ DỤNG ---
        [Range(1, int.MaxValue, ErrorMessage = "Giới hạn sử dụng phải lớn hơn 0 nếu có.")]
        public int? UsageLimit { get; set; } // Tổng số lần khuyến mãi này có thể được sử dụng. Nullable = không giới hạn.

        public int CurrentUsageCount { get; set; } = 0; // Số lần khuyến mãi này đã được sử dụng.

        [Range(1, int.MaxValue, ErrorMessage = "Giới hạn sử dụng mỗi người phải lớn hơn 0 nếu có.")]
        public int? UsageLimitPerUser { get; set; } // Số lần tối đa mỗi người dùng có thể sử dụng. Nullable = không giới hạn.
                                                    // ---------------------------

        public int? RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // --- NAVIGATION PROPERTIES CHO ÁP DỤNG ITEM/CATEGORY (SẼ TẠO MODEL CHO CHÚNG TIẾP THEO) ---
        public virtual ICollection<PromotionApplicableItem> ApplicableItems { get; set; }
        public virtual ICollection<PromotionApplicableCategory> ApplicableCategories { get; set; }
        // ------------------------------------------------------------------------------------

        // Navigation property để theo dõi các UserPromotionUsage
        public virtual ICollection<UserPromotionUsage> UserUsages { get; set; }


        public Promotion()
        {
            ApplicableItems = new HashSet<PromotionApplicableItem>();
            ApplicableCategories = new HashSet<PromotionApplicableCategory>();
            UserUsages = new HashSet<UserPromotionUsage>();
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
            IsActive = true;
        }
    }
}
