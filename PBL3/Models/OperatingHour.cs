using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class OperatingHour
    {
        public int Id { get; set; }

        [Required]
        public int RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        [Required(ErrorMessage = "Vui lòng chọn ngày trong tuần.")]
        public DayOfWeek DayOfWeek { get; set; }

        [Required(ErrorMessage = "Vui lòng nhập giờ mở cửa.")]
        // Lưu dưới dạng TimeSpan để dễ dàng so sánh và tính toán.
        // Khi hiển thị có thể format thành chuỗi giờ:phút.
        public TimeSpan OpenTime { get; set; } // Ví dụ: new TimeSpan(9, 0, 0) cho 9:00 AM

        [Required(ErrorMessage = "Vui lòng nhập giờ đóng cửa.")]
        public TimeSpan CloseTime { get; set; } // Ví dụ: new TimeSpan(22, 30, 0) cho 10:30 PM

        // Ghi chú cho khung giờ này (ví dụ: "Giờ vàng", "Chỉ phục vụ mang đi")
        [StringLength(100)]
        public string? Notes { get; set; }
    }
}
