namespace PBL3.Models.Common
{
    public class RestaurantCreationResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public int? CreatedRestaurantId { get; set; }
    }
}
