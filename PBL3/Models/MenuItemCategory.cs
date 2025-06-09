using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class MenuItemCategory
    {
        // Composite Primary Key được định nghĩa trong DbContext bằng Fluent API
        public int MenuItemId { get; set; }
        [ForeignKey("MenuItemId")]
        public virtual MenuItem MenuItem { get; set; }

        public int CategoryId { get; set; }
        [ForeignKey("CategoryId")]
        public virtual Category Category { get; set; }
    }
}
