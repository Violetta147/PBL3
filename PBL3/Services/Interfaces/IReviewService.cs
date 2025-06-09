using PBL3.Models.Common;
using PBL3.ViewModel.Review;

namespace PBL3.Services.Interfaces
{
    public interface IReviewService
    {
        Task<GenericResult> CreateReviewAsync(CreateReviewViewModel model, string userId);

        Task<IEnumerable<UserReviewListItemViewModel>> GetUserReviewsAsync(string userId);

        Task<GenericResult> DeleteReviewAsync(int reviewId, string userId);

        Task<EditReviewViewModel?> GetReviewForEditAsync(int reviewId, string userId);

        Task<GenericResult> UpdateReviewAsync(EditReviewViewModel model, string userId);

    }
}
