using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class OrderLog
    {
        public int Id { get; set; } // OrderStatusHistoryID theo UML của bạn

        [Required]
        public int OrderId { get; set; } // Lịch sử này của đơn hàng nào
        [ForeignKey("OrderId")]
        public virtual Order Order { get; set; }

        [Required]
        public OrderStatus Status { get; set; } // Trạng thái đã thay đổi thành (sử dụng enum OrderStatus)

        public DateTime StatusChangeTime { get; set; } = DateTime.UtcNow; // Thời điểm thay đổi trạng thái

        // Người thực hiện thay đổi trạng thái (tùy chọn, nhưng rất hữu ích)
        // Có thể là khách hàng (hủy đơn), nhân viên nhà hàng, admin, hoặc hệ thống tự động.
        public string ChangedByUserId { get; set; } // Nullable, vì có thể hệ thống tự động thay đổi
        [ForeignKey("ChangedByUserId")]
        public virtual AppUser ChangedByUser { get; set; }

        [StringLength(500)]
        public string Notes { get; set; } // Ghi chú cho việc thay đổi trạng thái
                                          // Ví dụ: "Khách hàng yêu cầu hủy do đặt nhầm."
                                          // "Nhà hàng hết món A, đã liên hệ khách đổi món B."
    }
}
