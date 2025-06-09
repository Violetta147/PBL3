using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class RestaurantTag
    {
        // Composite Primary Key sẽ được định nghĩa trong DbContext bằng Fluent API
        public int RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }

        public int TagId { get; set; }
        [ForeignKey("TagId")]
        public virtual Tag Tag { get; set; }
    }
}
