using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class RestaurantCuisine
    {
        // Composite Primary Key sẽ được định nghĩa trong DbContext bằng Fluent API
        public int RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        public int CuisineTypeId { get; set; }
        [ForeignKey("CuisineTypeId")]
        public virtual CuisineType CuisineType { get; set; }
    }
}
