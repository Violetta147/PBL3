using PBL3.Models;

namespace PBL3.Extensions
{
    public static class RestaurantStatusExtensions
    {
        public static string ToVietnameseRestaurantStatus(this RestaurantStatus status)
        {
            return status switch
            {
                RestaurantStatus.Open => "Đang mở cửa",
                RestaurantStatus.TemporarilyClosed => "Tạm đóng cửa",
                RestaurantStatus.ClosedPermanently => "Đóng cửa vĩnh viễn",
                _ => status.ToString(),
            };
        }
    }
}
