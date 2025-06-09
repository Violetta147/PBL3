using System.ComponentModel.DataAnnotations.Schema;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public enum PaymentMethod
    {
        [Display(Name = "Thanh toán khi nhận hàng")]
        COD,        // Cash On Delivery
        [Display(Name = "Thanh toán bằng thẻ tín dụng")]
        CreditCard,
        [Display(Name = "Thanh toán bằng thẻ ghi nợ")]
        DebitCard,
        [Display(Name = "Chuyển khoản qua ngân hàng")]
        BankTransfer,
        [Display(Name = "Thanh toán bằng ví điện tử")]
        EWallet
    }

    public class Order
    {
        public int Id { get; set; } // orderID theo UML của bạn

        [Required]
        public string UserId { get; set; } // Người dùng đặt hàng
        [ForeignKey("UserId")]
        public virtual AppUser User { get; set; }

        [Required]
        public int RestaurantId { get; set; } // Nhà hàng xử lý đơn hàng này
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        public DateTime OrderDate { get; set; } = DateTime.UtcNow;

        [Required]
        public OrderStatus CurrentStatus { get; set; } // Trạng thái hiện tại của đơn hàng

        [StringLength(500)]
        public string Note { get; set; } // Ghi chú của khách hàng cho toàn bộ đơn hàng

        // Thông tin người nhận và địa chỉ giao hàng
        [Required(ErrorMessage = "Vui lòng nhập tên người nhận")]
        [StringLength(100, MinimumLength = 2, ErrorMessage = "Tên người nhận phải có ít nhất 2 ký tự.")]
        public string ReceiverName { get; set; } // Có thể mặc định là DisplayName của User

        [Required(ErrorMessage = "Vui lòng nhập số điện thoại người nhận")]
        [Phone(ErrorMessage = "Số điện thoại người nhận không hợp lệ.")]
        [StringLength(20)]
        public string ReceiverPhoneNumber { get; set; }

        [Required(ErrorMessage = "Vui lòng chọn địa chỉ giao hàng.")]
        public int ShippingAddressId { get; set; } // Khóa ngoại đến bảng Addresses
        [ForeignKey("ShippingAddressId")]
        public virtual Address ShippingAddress { get; set; }

        public int? AppliedPromotionId { get; set; }
        [ForeignKey("AppliedPromotionId")] 
        public virtual Promotion AppliedPromotion { get; set; }
        // Chi tiết các loại phí
        [Column(TypeName = "decimal(18,2)")]
        public decimal Subtotal { get; set; } // Tổng tiền các OrderLines (trước phí, thuế, giảm giá)

        [Column(TypeName = "decimal(18,2)")]
        public decimal DeliveryFee { get; set; } = 0; // Phí giao hàng

        [Column(TypeName = "decimal(18,2)")]
        public decimal ServiceFee { get; set; } = 0; // Phí dịch vụ (nếu có)

        [Column(TypeName = "decimal(18,2)")]
        public decimal TaxAmount { get; set; } = 0; // Tiền thuế (nếu có)

        [Column(TypeName = "decimal(18,2)")]
        public decimal DiscountAmount { get; set; } = 0; // Số tiền được giảm giá (ví dụ từ voucher)

        [StringLength(50)]
        public string AppliedCouponCode { get; set; } // Đổi tên từ DiscountCode để rõ hơn là mã đã áp dụng

        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal TotalAmount { get; set; } // Tổng tiền cuối cùng (Subtotal + DeliveryFee + ServiceFee + TaxAmount - DiscountAmount)

        // Thông tin thanh toán
        public PaymentMethod? PaymentMethod { get; set; } // Phương thức thanh toán (nullable nếu chưa thanh toán hoặc COD)

        [StringLength(100)]
        public string TransactionId { get; set; } // Mã giao dịch từ cổng thanh toán (nếu có)

        public bool IsPaid { get; set; } = false; // Đã thanh toán hay chưa?

        // Thời gian dự kiến giao hàng (nếu có)
        public DateTime? EstimatedDeliveryTime { get; set; }

        // Thời gian giao hàng thực tế (cập nhật khi đơn hàng được giao)
        public DateTime? ActualDeliveryTime { get; set; }


        // Navigation Properties
        public virtual ICollection<OrderLine> OrderLines { get; set; } // Các món trong đơn hàng
        public virtual ICollection<OrderLog> OrderLogs { get; set; } // Lịch sử trạng thái đơn hàng

        public Order()
        {
            OrderLines = new HashSet<OrderLine>();
            OrderLogs = new HashSet<OrderLog>();
            CurrentStatus = OrderStatus.PendingConfirmation; // Trạng thái mặc định khi mới tạo
        }
    }
}
