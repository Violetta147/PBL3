using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using CloudinaryDotNet.Actions;
using PBL3.Models.Common;

namespace PBL3.Services.Interfaces
{
    // Model đơn giản để trả về kết quả upload (có thể dùng class riêng hoặc Tuple)
    public class AppImageUploadResult
    {
        public bool Success { get; set; }
        public string PublicId { get; set; } // ID của ảnh trên Cloudinary
        public string Url { get; set; }      // URL của ảnh trên Cloudinary
        public string ErrorMessage { get; set; }
    }

    public interface IPhotoService
    {
        Task<AppImageUploadResult> UploadPhotoAsync(IFormFile file, string folderName);
        Task<GenericResult> DeletePhotoAsync(string publicId);
    }
}
