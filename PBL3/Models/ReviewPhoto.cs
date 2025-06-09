using System;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace PBL3.Models
{
    public class ReviewPhoto
    {
        public int Id { get; set; }

        [Required]
        [StringLength(500)]
        public string Url { get; set; }

        [Required(ErrorMessage = "Cloudinary Public ID không được để trống.")]
        [StringLength(200)]
        public string CloudinaryPublicId { get; set; }

        [StringLength(500)]
        public string? Caption { get; set; }

        public DateTime UploadedDate { get; set; } = DateTime.UtcNow;

        [Required]
        public int ReviewId { get; set; }
        [ForeignKey("ReviewId")]
        public virtual Review Review { get; set; }
    }
}
