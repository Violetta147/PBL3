using CloudinaryDotNet; // Thư viện Cloudinary
using CloudinaryDotNet.Actions; // Cho ImageUploadParams, DeletionParams
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options; // Cho IOptions<CloudinarySettings>
using PBL3.Models.Settings; // Namespace của CloudinarySettings
using System.Threading.Tasks;
using PBL3.Models.Common; // Cho GenericResult
using PBL3.Services.Interfaces;

namespace PBL3.Services.Implementations
{
    public class CloudinaryPhotoService : IPhotoService
    {
        private readonly Cloudinary _cloudinary;

        // Sử dụng IOptions để inject CloudinarySettings từ appsettings.json
        public CloudinaryPhotoService(IOptions<CloudinarySettings> config)
        {
            // Tạo một Account object từ CloudinarySettings
            var acc = new Account(
                config.Value.CloudName,
                config.Value.ApiKey,
                config.Value.ApiSecret
            );
            _cloudinary = new Cloudinary(acc); // Khởi tạo Cloudinary client
        }

        public async Task<AppImageUploadResult> UploadPhotoAsync(IFormFile file, string folderName)
        {
            var uploadResult = new AppImageUploadResult();

            if (file == null || file.Length == 0)
            {
                uploadResult.Success = false;
                uploadResult.ErrorMessage = "No file selected or file is empty.";
                return uploadResult;
            }

            // Tạo một stream từ IFormFile
            using (var stream = file.OpenReadStream())
            {
                // Định nghĩa các tham số upload
                var uploadParams = new ImageUploadParams()
                {
                    File = new FileDescription(file.FileName, stream), // Tên file và stream
                    Folder = folderName, // Chỉ định thư mục trên Cloudinary
                                         // Bạn có thể thêm các transformations ở đây nếu muốn (ví dụ: resize, crop)
                                         // Transformation = new Transformation().Width(500).Height(500).Crop("fill").Gravity("face")
                };

                // Thực hiện upload
                var result = await _cloudinary.UploadAsync(uploadParams);

                if (result.Error != null)
                {
                    uploadResult.Success = false;
                    uploadResult.ErrorMessage = result.Error.Message;
                    return uploadResult;
                }

                uploadResult.Success = true;
                uploadResult.PublicId = result.PublicId;
                uploadResult.Url = result.SecureUrl.ToString(); // Hoặc result.Url.ToString() nếu không cần https
            }
            return uploadResult;
        }

        public async Task<GenericResult> DeletePhotoAsync(string publicId)
        {
            var deleteResult = new GenericResult();
            if (string.IsNullOrEmpty(publicId))
            {
                deleteResult.Success = false;
                deleteResult.ErrorMessage = "PublicId cannot be null or empty.";
                return deleteResult;
            }

            // Định nghĩa các tham số xóa
            var deletionParams = new DeletionParams(publicId);

            // Thực hiện xóa
            var result = await _cloudinary.DestroyAsync(deletionParams);

            if (result.Result == "ok" || result.Result == "not found") // "not found" cũng coi là thành công vì ảnh không còn đó
            {
                deleteResult.Success = true;
            }
            else
            {
                deleteResult.Success = false;
                deleteResult.ErrorMessage = result.Error?.Message ?? "Failed to delete photo from Cloudinary.";
            }
            return deleteResult;
        }
    }
}
