using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public enum PromotionType
    {
        // Giảm giá trên toàn bộ đơn hàng
        [Display(Name = "Giảm % tổng đơn")]
        PercentageOffOrder,
        [Display(Name = "Giảm tiền cố định tổng đơn")]
        FixedAmountOffOrder,

        // Giảm giá cho từng món ăn/danh mục
        [Display(Name = "Giảm % cho món")]
        PercentageOffItem,
        [Display(Name = "Giảm tiền cố định cho món")]
        FixedAmountOffItem,

        // Các loại khác
        [Display(Name = "Miễn phí vận chuyển")]
        FreeShipping,
        // BuyXGetYProduct // (Để sau nếu cần)
    }
}
