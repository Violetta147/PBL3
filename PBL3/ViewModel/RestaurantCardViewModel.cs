using System.Collections.Generic;
using PBL3.Models;

namespace PBL3.ViewModel
{    public class RestaurantCardViewModel
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? FullAddress { get; set; }

        //MainImageUrl
        public string? CardImageUrl { get; set; }
        public List<string?>? CuisineSummary { get; set; } // e.g., "Italian, Pizza"
        public double AverageRating { get; set; }
        public int ReviewCount { get; set; }
        public decimal? MinTypicalPrice { get; set; } = 0;
        public decimal? MaxTypicalPrice { get; set; } = 0;
        
        // Add missing properties for the partial view
        public double? Latitude { get; set; }
        public double? Longitude { get; set; } 
        public string? PriceRange
        {
            get
            {
                // Kiểm tra cả HasValue và giá trị không phải 0
                bool hasMinPrice = MinTypicalPrice.HasValue && MinTypicalPrice != 0;
                bool hasMaxPrice = MaxTypicalPrice.HasValue && MaxTypicalPrice != 0;

                if (hasMinPrice && hasMaxPrice)
                {
                    if (MinTypicalPrice == MaxTypicalPrice)
                        return $"{MinTypicalPrice:N0} VNĐ";
                    return $"{MinTypicalPrice:N0} - {MaxTypicalPrice:N0} VNĐ";
                }
                if (hasMinPrice)
                    return $"Từ {MinTypicalPrice:N0} VNĐ";
                if (hasMaxPrice)
                    return $"Đến {MaxTypicalPrice:N0} VNĐ";
                return "Chưa cập nhật";
            }
        }
        
        public decimal? AveragePrice
        {
            get
            {
                if (MinTypicalPrice == 0 && MaxTypicalPrice == 0)
                {
                    return 0;
                }
                return (MinTypicalPrice + MaxTypicalPrice) / 2;
            }
        }
        public RestaurantStatus Status { get; set; }
        public ICollection<CuisineType>? Cuisines { get; set; }
        public ICollection<Tag>? Tags { get; set; }

        public ICollection<OperatingHour>? OperatingHours { get; set; }
    }
}
