using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PBL3.Data;
using PBL3.Models;
using PBL3.Models.Common;
using PBL3.Services.Interfaces;
using PBL3.ViewModel.Review;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.Services.Implementations
{
    public class ReviewService : IReviewService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<AppUser> _userManager;
        private readonly IPhotoService _photoService;
        private readonly ILogger<ReviewService> _logger;

        public ReviewService(
            ApplicationDbContext context,
            UserManager<AppUser> userManager,
            IPhotoService photoService,
            ILogger<ReviewService> logger)
        {
            _context = context;
            _userManager = userManager;
            _photoService = photoService;
            _logger = logger;
        }

        public async Task<GenericResult> CreateReviewAsync(CreateReviewViewModel model, string userId)
        {
            var restaurant = await _context.Restaurants.FirstOrDefaultAsync(r => r.Id == model.RestaurantId);
            if (restaurant == null)
            {
                _logger.LogWarning("CreateReviewAsync: Restaurant ID {RestaurantId} not found.", model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy nhà hàng để đánh giá." };
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("CreateReviewAsync: User ID {UserId} not found.", userId);
                return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy thông tin người dùng." };
            }

            bool alreadyReviewed = await _context.Reviews.AnyAsync(r => r.RestaurantId == model.RestaurantId && r.UserId == userId);
            if (alreadyReviewed)
            {
                _logger.LogInformation("CreateReviewAsync: User {UserId} already reviewed Restaurant {RestaurantId}.", userId, model.RestaurantId);
                return new GenericResult { Success = false, ErrorMessage = "Bạn đã gửi đánh giá cho nhà hàng này rồi." };
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var reviewEntity = new Review
                {
                    RestaurantId = model.RestaurantId,
                    UserId = userId,
                    Rating = model.Rating,
                    Comment = model.Comment, // ViewModel có Comment là nullable
                    ReviewDate = DateTime.UtcNow,
                    Photos = new List<ReviewPhoto>()
                };
                _context.Reviews.Add(reviewEntity);
                await _context.SaveChangesAsync(); // Lấy reviewEntity.Id

                if (model.Photos != null && model.Photos.Any())
                {
                    string imageFolder = $"restaurants/{model.RestaurantId}/reviews/{reviewEntity.Id}";
                    foreach (var photoFile in model.Photos)
                    {
                        if (photoFile != null && photoFile.Length > 0)
                        {
                            var uploadResult = await _photoService.UploadPhotoAsync(photoFile, imageFolder);
                            if (uploadResult.Success && !string.IsNullOrEmpty(uploadResult.Url) && !string.IsNullOrEmpty(uploadResult.PublicId))
                            {
                                var reviewPhoto = new ReviewPhoto
                                {
                                    ReviewId = reviewEntity.Id,
                                    Url = uploadResult.Url,
                                    CloudinaryPublicId = uploadResult.PublicId,
                                    UploadedDate = DateTime.UtcNow,
                                    Caption = $"Ảnh review cho {restaurant.Name}"
                                };
                                _context.ReviewPhotos.Add(reviewPhoto);
                            }
                            else
                            {
                                await transaction.RollbackAsync();
                                _logger.LogWarning("Lỗi tải ảnh '{FileName}' cho review của nhà hàng {RestaurantId}: {Error}",
                                    photoFile.FileName, model.RestaurantId, uploadResult.ErrorMessage);
                                return new GenericResult { Success = false, ErrorMessage = $"Lỗi tải ảnh: {uploadResult.ErrorMessage}. Đánh giá chưa được lưu." };
                            }
                        }
                    }
                }

                // Cập nhật Restaurant Rating và Count
                var reviewsForRestaurant = await _context.Reviews
                                                     .Where(r => r.RestaurantId == model.RestaurantId)
                                                     .AsNoTracking()
                                                     .ToListAsync();

                restaurant.AverageRating = reviewsForRestaurant.Any() ? reviewsForRestaurant.Average(r => r.Rating) : 0;
                restaurant.ReviewCount = reviewsForRestaurant.Count;
                restaurant.UpdatedAt = DateTime.UtcNow;
                _context.Restaurants.Update(restaurant);

                await _context.SaveChangesAsync(); // Lưu ReviewPhoto và cập nhật Restaurant
                await transaction.CommitAsync();

                _logger.LogInformation("Review (ID: {ReviewId}) created successfully for Restaurant ID {RestaurantId} by User ID {UserId}", reviewEntity.Id, model.RestaurantId, userId);
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Lỗi khi tạo review cho nhà hàng ID {RestaurantId} bởi User ID {UserId}. Model: {@ReviewModel}", model.RestaurantId, userId, model);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi hệ thống xảy ra khi gửi đánh giá." };
            }
        }

        public async Task<IEnumerable<UserReviewListItemViewModel>> GetUserReviewsAsync(string userId)
        {
            var reviews = await _context.Reviews
                .Where(r => r.UserId == userId)
                .Include(r => r.Restaurant) // Để lấy Restaurant.Name, Restaurant.MainImageUrl
                                            // .ThenInclude(resto => resto.Address) // Không cần Address cho UserReviewListItemViewModel hiện tại
                .Include(r => r.Photos) // ReviewPhoto, để lấy ReviewPhotoUrls
                .OrderByDescending(r => r.ReviewDate)
                .AsNoTracking()
                .ToListAsync();

            return reviews.Select(r => new UserReviewListItemViewModel
            {
                ReviewId = r.Id,
                RestaurantId = r.RestaurantId,
                RestaurantName = r.Restaurant?.Name ?? "N/A", // Kiểm tra null cho Restaurant
                RestaurantImageUrl = r.Restaurant?.MainImageUrl, // Lấy ảnh từ Restaurant entity
                Rating = r.Rating,
                Comment = r.Comment,
                ReviewDate = r.ReviewDate,
                ReviewPhotoUrls = r.Photos?.Select(p => p.Url).ToList() ?? new List<string>(),

                // Tạo URL tương đối.
                // Controller sẽ xử lý việc tạo URL đầy đủ nếu cần,
                // hoặc View sẽ dùng asp-controller, asp-action, asp-route-id.
                // Việc ViewModel chứa URL sẵn giúp View đơn giản hơn.
                ViewRestaurantUrl = $"/Restaurants/Details/{r.RestaurantId}", // URL đến trang chi tiết nhà hàng
                EditReviewUrl = $"/Reviews/EditReview/{r.Id}",      // URL đến trang sửa review (sẽ tạo sau)
                DeleteReviewUrl = $"/Reviews/DeleteReview/{r.Id}"     // URL cho action xóa review (sẽ tạo sau)
            }).ToList();
        }

        public async Task<GenericResult> DeleteReviewAsync(int reviewId, string userId)
        {
            var reviewToDelete = await _context.Reviews
                                        .Include(r => r.Photos) // Để xóa ảnh trên Cloudinary
                                        .Include(r => r.Restaurant) // Để cập nhật lại rating của nhà hàng
                                        .FirstOrDefaultAsync(r => r.Id == reviewId);

            if (reviewToDelete == null)
            {
                return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy đánh giá để xóa." };
            }

            // Kiểm tra quyền: chỉ người viết review hoặc Admin mới được xóa
            // (Giả sử Admin có quyền xóa mọi review - logic này có thể phức tạp hơn)
            var isAdmin = await _userManager.IsInRoleAsync(await _userManager.FindByIdAsync(userId), "Admin");
            if (reviewToDelete.UserId != userId && !isAdmin)
            {
                _logger.LogWarning("User {UserId} attempted to delete review {ReviewId} not owned by them.", userId, reviewId);
                return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền xóa đánh giá này." };
            }

            var restaurantToUpdate = reviewToDelete.Restaurant; // Giữ lại tham chiếu trước khi xóa review

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // 1. Xóa ảnh trên Cloudinary
                if (reviewToDelete.Photos.Any())
                {
                    foreach (var photo in reviewToDelete.Photos.ToList()) // ToList() để tránh lỗi modify collection
                    {
                        if (!string.IsNullOrEmpty(photo.CloudinaryPublicId))
                        {
                            await _photoService.DeletePhotoAsync(photo.CloudinaryPublicId);
                        }
                        // _context.ReviewPhotos.Remove(photo); // Sẽ bị xóa theo Cascade từ Review
                    }
                }

                // 2. Xóa Review (EF Core sẽ xóa ReviewPhotos do Cascade)
                _context.Reviews.Remove(reviewToDelete);
                await _context.SaveChangesAsync(); // Lưu thay đổi xóa Review và ReviewPhotos

                // 3. Cập nhật lại AverageRating và ReviewCount cho Restaurant
                if (restaurantToUpdate != null)
                {
                    var reviewsForRestaurant = await _context.Reviews
                                                         .Where(r => r.RestaurantId == restaurantToUpdate.Id)
                                                         .AsNoTracking()
                                                         .ToListAsync();

                    restaurantToUpdate.AverageRating = reviewsForRestaurant.Any() ? reviewsForRestaurant.Average(r => r.Rating) : 0;
                    restaurantToUpdate.ReviewCount = reviewsForRestaurant.Count;
                    restaurantToUpdate.UpdatedAt = DateTime.UtcNow;
                    _context.Restaurants.Update(restaurantToUpdate);
                    await _context.SaveChangesAsync(); // Lưu thay đổi của Restaurant
                }

                await transaction.CommitAsync();
                _logger.LogInformation("Review (ID: {ReviewId}) deleted successfully by User ID: {UserId}", reviewId, userId);
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Lỗi khi xóa review ID {ReviewId} bởi User ID {UserId}", reviewId, userId);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi hệ thống xảy ra khi xóa đánh giá." };
            }
        }

        public async Task<EditReviewViewModel?> GetReviewForEditAsync(int reviewId, string userId)
        {
            var review = await _context.Reviews
                                   .Include(r => r.Restaurant) // Để lấy tên nhà hàng
                                   .Include(r => r.Photos)     // Để lấy danh sách ảnh hiện tại
                                   .AsNoTracking()
                                   .FirstOrDefaultAsync(r => r.Id == reviewId);

            if (review == null)
            {
                _logger.LogWarning("GetReviewForEdit: Review with ID {ReviewId} not found.", reviewId);
                return null;
            }

            // Kiểm tra quyền: Chỉ người viết review hoặc Admin mới được sửa
            // (Giả sử Admin có thể sửa mọi review - cần logic phân quyền phức tạp hơn nếu có)
            var isAdmin = await _userManager.IsInRoleAsync(await _userManager.FindByIdAsync(userId), "Admin");
            if (review.UserId != userId && !isAdmin)
            {
                _logger.LogWarning("User {UserId} attempted to edit review {ReviewId} not owned by them.", userId, reviewId);
                return null;
            }

            return new EditReviewViewModel
            {
                ReviewId = review.Id,
                RestaurantId = review.RestaurantId,
                RestaurantName = review.Restaurant?.Name,
                Rating = review.Rating,
                Comment = review.Comment,
                ReviewDate = review.ReviewDate, // Hiển thị ngày review gốc
                CurrentPhotos = review.Photos.Select(p => new ReviewPhotoViewModel
                {
                    Id = p.Id,
                    Url = p.Url,
                    CloudinaryPublicId = p.CloudinaryPublicId,
                    IsMarkedForDeletion = false
                }).ToList(),
                NewPhotos = new List<IFormFile>() // Khởi tạo rỗng cho form
            };
        }

        public async Task<GenericResult> UpdateReviewAsync(EditReviewViewModel model, string userId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var reviewToUpdate = await _context.Reviews
                                            .Include(r => r.Restaurant) // Để cập nhật rating
                                            .Include(r => r.Photos)     // Để quản lý ảnh
                                            .FirstOrDefaultAsync(r => r.Id == model.ReviewId);

                if (reviewToUpdate == null)
                {
                    await transaction.RollbackAsync();
                    return new GenericResult { Success = false, ErrorMessage = "Không tìm thấy đánh giá để cập nhật." };
                }

                // Kiểm tra quyền (người viết review hoặc Admin)
                var isAdmin = await _userManager.IsInRoleAsync(await _userManager.FindByIdAsync(userId), "Admin");
                if (reviewToUpdate.UserId != userId && !isAdmin)
                {
                    await transaction.RollbackAsync();
                    _logger.LogWarning("UpdateReviewAsync: User {UserId} attempted to update review {ReviewId} not owned or not admin.", userId, model.ReviewId);
                    return new GenericResult { Success = false, ErrorMessage = "Bạn không có quyền chỉnh sửa đánh giá này." };
                }

                // 1. Cập nhật thông tin cơ bản của Review
                reviewToUpdate.Rating = model.Rating;
                reviewToUpdate.Comment = model.Comment;
                // ReviewDate có thể không cho sửa, hoặc cập nhật thành ngày sửa đổi
                // reviewToUpdate.ReviewDate = DateTime.UtcNow; // Nếu muốn cập nhật ngày

                // 2. Xử lý xóa ảnh cũ (CurrentPhotos với IsMarkedForDeletion = true)
                if (model.CurrentPhotos != null)
                {
                    foreach (var photoVM in model.CurrentPhotos.Where(p => p.IsMarkedForDeletion))
                    {
                        var photoEntity = reviewToUpdate.Photos.FirstOrDefault(p => p.Id == photoVM.Id);
                        if (photoEntity != null)
                        {
                            if (!string.IsNullOrEmpty(photoEntity.CloudinaryPublicId))
                            {
                                await _photoService.DeletePhotoAsync(photoEntity.CloudinaryPublicId);
                            }
                            _context.ReviewPhotos.Remove(photoEntity); // Xóa khỏi DB
                        }
                    }
                }

                // 3. Xử lý upload ảnh mới (NewPhotos)
                bool imageUploadError = false;
                if (model.NewPhotos != null && model.NewPhotos.Any())
                {
                    string imageFolder = $"restaurants/{reviewToUpdate.RestaurantId}/reviews/{reviewToUpdate.Id}";
                    foreach (var photoFile in model.NewPhotos)
                    {
                        if (photoFile != null && photoFile.Length > 0)
                        {
                            var uploadResult = await _photoService.UploadPhotoAsync(photoFile, imageFolder);
                            if (uploadResult.Success && !string.IsNullOrEmpty(uploadResult.Url) && !string.IsNullOrEmpty(uploadResult.PublicId))
                            {
                                reviewToUpdate.Photos.Add(new ReviewPhoto // Thêm vào collection của entity
                                {
                                    ReviewId = reviewToUpdate.Id, // Hoặc Review = reviewToUpdate
                                    Url = uploadResult.Url,
                                    CloudinaryPublicId = uploadResult.PublicId,
                                    UploadedDate = DateTime.UtcNow
                                });
                            }
                            else
                            {
                                imageUploadError = true;
                                _logger.LogWarning("Lỗi tải ảnh '{FileName}' khi cập nhật review {ReviewId}: {Error}", photoFile.FileName, reviewToUpdate.Id, uploadResult.ErrorMessage);
                                // Quyết định rollback ngay hay cho phép lưu các thay đổi khác
                            }
                        }
                    }
                    if (imageUploadError)
                    {
                        await transaction.RollbackAsync();
                        return new GenericResult { Success = false, ErrorMessage = "Có lỗi xảy ra khi tải lên ảnh mới. Thay đổi chưa được lưu." };
                    }
                }

                // 4. Cập nhật lại AverageRating và ReviewCount cho Restaurant
                var restaurantToUpdate = reviewToUpdate.Restaurant; // Đã Include
                if (restaurantToUpdate != null)
                {
                    // Lấy lại tất cả review (bao gồm cả review vừa sửa) để tính toán chính xác
                    var reviewsForRestaurant = await _context.Reviews
                                                         .Where(r => r.RestaurantId == restaurantToUpdate.Id)
                                                         .AsNoTracking()
                                                         .ToListAsync();
                    restaurantToUpdate.AverageRating = reviewsForRestaurant.Any() ? reviewsForRestaurant.Average(r => r.Rating) : 0;
                    restaurantToUpdate.ReviewCount = reviewsForRestaurant.Count; // Số lượng review không đổi khi sửa, chỉ đổi khi xóa/thêm mới hoàn toàn
                    restaurantToUpdate.UpdatedAt = DateTime.UtcNow;
                    _context.Restaurants.Update(restaurantToUpdate);
                }

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("Review (ID: {ReviewId}) updated successfully by User ID: {UserId}", model.ReviewId, userId);
                return new GenericResult { Success = true };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Lỗi khi cập nhật review ID {ReviewId} bởi User ID {UserId}. Model: {@EditReviewModel}", model.ReviewId, userId, model);
                return new GenericResult { Success = false, ErrorMessage = "Đã có lỗi hệ thống xảy ra khi cập nhật đánh giá." };
            }
        }

    }
}
