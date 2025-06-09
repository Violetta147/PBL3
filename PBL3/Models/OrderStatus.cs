namespace PBL3.Models
{
    public enum OrderStatus
    {
        PendingConfirmation,    // Chờ xác nhận (VD: Nhà hàng chưa chấp nhận đơn)
        Preparing,              // Đang chuẩn bị (Nhà hàng đã chấp nhận và đang làm)
        ReadyForPickup,         // Sẵn sàng để lấy (Nếu có tùy chọn tự đến lấy)
        OutForDelivery,         // Đang giao
        Delivered,              // Đã giao thành công
        CancelledByCustomer,    // Khách hàng đã hủy
        CancelledByRestaurant,  // Nhà hàng đã hủy
        FailedDelivery,         // Giao hàng thất bại
        Completed               // Đã hoàn thành (Sau khi đã giao và không có vấn đề gì thêm, có thể dùng thay cho Delivered)
    }
}
