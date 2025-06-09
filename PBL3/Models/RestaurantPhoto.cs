using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PBL3.Models
{
    public class RestaurantPhoto
    {
        public int Id { get; set; }

        [Required]
        [StringLength(500)]
        public string Url { get; set; }

        [Required(ErrorMessage = "Cloudinary Public ID không được để trống.")]
        [StringLength(200)] // Kiểm tra lại độ dài thực tế của Public ID từ Cloudinary
        public string CloudinaryPublicId { get; set; } // PublicId từ Cloudinary

        [StringLength(500)]
        public string Caption { get; set; }

        public DateTime UploadedDate { get; set; } = DateTime.UtcNow;
        public bool IsCover { get; set; } // Có phải ảnh bìa không?

        [Required]
        public int RestaurantId { get; set; }
        [ForeignKey("RestaurantId")]
        public virtual Restaurant Restaurant { get; set; }
    }
}
