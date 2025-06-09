using System;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public class MenuItemPhoto
    {
        public int Id { get; set; }

        [Required]
        [StringLength(500)]
        public string Url { get; set; }

        [Required(ErrorMessage = "Cloudinary Public ID không được để trống.")]
        [StringLength(200)]
        public string CloudinaryPublicId { get; set; }

        [StringLength(500)]
        public string Caption { get; set; }

        public DateTime UploadedDate { get; set; } = DateTime.UtcNow;
        public bool IsMainImage { get; set; } // Ảnh chính của món ăn?

        [Required]
        public int MenuItemId { get; set; }
        [ForeignKey("MenuItemId")]
        public virtual MenuItem MenuItem { get; set; }
    }
}
