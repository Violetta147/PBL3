// Data/Seeders/ReviewSeeder.cs
using Microsoft.EntityFrameworkCore;
using PBL3.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.Data.Seeder
{
    public static class ReviewSeeder
    {
        private static Random _random = new Random();

        public static async Task SeedAsync(ApplicationDbContext context)
        {
            if (await context.Reviews.AnyAsync())
            {
                Console.WriteLine("Reviews đã được seed trước đó.");
                return;
            }

            var restaurants = await context.Restaurants.ToListAsync();
            var users = await context.Users.Where(u => !u.Email!.Contains("admin")).ToListAsync();

            if (!restaurants.Any() || !users.Any())
            {
                Console.WriteLine("Không có nhà hàng hoặc user để seed reviews.");
                return;
            }

            var reviews = new List<Review>();

            // Vietnamese review templates for different ratings
            var reviewTemplates = new Dictionary<int, List<string>>
            {
                [5] = new List<string>
                {
                    "Nhà hàng tuyệt vời! Thức ăn ngon, phục vụ tận tình. Sẽ quay lại lần sau.",
                    "Chất lượng món ăn xuất sắc, không gian thoáng mát. Đặc biệt ấn tượng với món đặc sản.",
                    "Một trải nghiệm ẩm thực tuyệt vời! Mọi món đều tươi ngon, đậm đà hương vị truyền thống.",
                    "Đồ ăn rất ngon, giá cả hợp lý. Nhân viên phục vụ nhiệt tình và chu đáo.",
                    "Không gian đẹp, món ăn ngon miệng. Đặc biệt thích món bún bò Huế ở đây.",
                    "Nhà hàng sạch sẽ, thức ăn tươi ngon. Phục vụ nhanh chóng và thân thiện.",
                    "Hài lòng từ món ăn đến dịch vụ. Sẽ giới thiệu cho bạn bè.",
                    "Chất lượng tuyệt vời, đáng đồng tiền bát gạo. Sẽ quay lại thường xuyên.",
                    "Món ăn đậm đà, không gian ấm cúng. Rất thích phong cách phục vụ ở đây.",
                    "Từ không gian đến món ăn đều hoàn hảo. Đây là nơi tôi hay đưa gia đình đến."
                },
                [4] = new List<string>
                {
                    "Nhà hàng khá ổn, thức ăn ngon. Chỉ có điều hơi đông nên chờ lâu một chút.",
                    "Món ăn ngon, giá hợp lý. Không gian hơi ồn nhưng vẫn chấp nhận được.",
                    "Đồ ăn tươi ngon, phục vụ tốt. Chỉ mong giờ cao điểm ít đông hơn.",
                    "Chất lượng ổn, vị hơi nhạt so với mong đợi nhưng vẫn ngon.",
                    "Nhà hàng sạch sẽ, thức ăn ngon. Có lẽ sẽ ghé lại lần sau.",
                    "Phục vụ nhiệt tình, món ăn khá ngon. Giá cả vừa phải.",
                    "Không gian đẹp, đồ ăn tươi. Chỉ có điều phải chờ hơi lâu.",
                    "Món ăn đa dạng, vị ngon. Thời gian phục vụ hơi chậm.",
                    "Nhà hàng ổn, giá cả hợp lý. Sẽ thử các món khác lần sau.",
                    "Chất lượng tốt, nhân viên thân thiện. Mong cải thiện tốc độ phục vụ."
                },
                [3] = new List<string>
                {
                    "Nhà hàng bình thường, thức ăn tạm ổn. Không có gì đặc biệt.",
                    "Đồ ăn vừa vừa, phục vụ chậm. Có thể cần cải thiện.",
                    "Giá cả hợp lý nhưng chất lượng chưa tương xứng.",
                    "Không gian ổn, món ăn vị bình thường. Không ấn tượng lắm.",
                    "Thức ăn tạm được, phục vụ cần cải thiện thái độ.",
                    "Nhà hàng sạch sẽ nhưng món ăn thiếu đậm đà.",
                    "Phục vụ ổn, đồ ăn hơi mặn. Cần điều chỉnh gia vị.",
                    "Không gian đẹp nhưng món ăn chưa đạt kỳ vọng.",
                    "Giá cả vừa phải, chất lượng trung bình khá.",
                    "Thử một lần, có thể sẽ tìm chỗ khác lần sau."
                },
                [2] = new List<string>
                {
                    "Thức ăn không ngon, phục vụ chậm chạp. Khá thất vọng.",
                    "Chất lượng kém, không đáng giá tiền. Sẽ không quay lại.",
                    "Đồ ăn nguội lạnh, nhân viên thờ ơ. Trải nghiệm không tốt.",
                    "Phục vụ thiếu chuyên nghiệp, món ăn không tươi.",
                    "Giá cả cao nhưng chất lượng không tương xứng.",
                    "Không gian ồn ào, thức ăn mặn quá. Cần cải thiện nhiều.",
                    "Chờ đợi quá lâu, khi có món thì đã nguội.",
                    "Thất vọng về cách phục vụ và chất lượng món ăn.",
                    "Không khuyến khích đến đây. Có nhiều lựa chọn tốt hơn.",
                    "Trải nghiệm không tốt, sẽ không giới thiệu cho ai."
                },
                [1] = new List<string>
                {
                    "Rất tệ! Thức ăn dở, phục vụ thái độ. Không bao giờ quay lại.",
                    "Kinh khủng! Đồ ăn không tươi, nhân viên cực kỳ thờ ơ.",
                    "Thất vọng hoàn toàn! Chất lượng tệ hại, lãng phí tiền.",
                    "Phục vụ tệ, thức ăn khó nuốt. Trải nghiệm kinh khủng.",
                    "Không thể tệ hơn! Từ phục vụ đến đồ ăn đều dưới mức kỳ vọng.",
                    "Tuyệt đối không nên đến! Thức ăn tanh, phục vụ thô lỗ.",
                    "Lãng phí tiền và thời gian. Chất lượng quá tệ.",
                    "Không gian bẩn thỉu, đồ ăn không thể ăn được.",
                    "Đây là trải nghiệm tệ nhất từng có. Tránh xa!",
                    "Tệ đến mức không thể mô tả được. Chắc chắn không quay lại."
                }
            };

            Console.WriteLine("Bắt đầu seed reviews...");

            foreach (var restaurant in restaurants)
            {
                // Generate 15-50 reviews per restaurant
                var reviewCount = _random.Next(15, 51);
                var restaurantUsers = users.OrderBy(x => Guid.NewGuid()).Take(reviewCount).ToList();

                foreach (var user in restaurantUsers)
                {
                    // Generate realistic rating distribution
                    // 15% 5-star, 25% 4-star, 35% 3-star, 15% 2-star, 10% 1-star
                    var ratingRoll = _random.NextDouble();
                    int rating;
                    if (ratingRoll < 0.15) rating = 5;      // 15% - 5 stars
                    else if (ratingRoll < 0.40) rating = 4; // 25% - 4 stars  
                    else if (ratingRoll < 0.75) rating = 3; // 35% - 3 stars
                    else if (ratingRoll < 0.90) rating = 2; // 15% - 2 stars
                    else rating = 1;                        // 10% - 1 star

                    var template = reviewTemplates[rating][_random.Next(reviewTemplates[rating].Count)];
                    
                    // Randomize review date (last 2 years)
                    var reviewDate = DateTime.UtcNow.AddDays(-_random.Next(1, 730));

                    var review = new Review
                    {
                        UserId = user.Id,
                        RestaurantId = restaurant.Id,
                        Rating = rating,
                        Comment = template,
                        ReviewDate = reviewDate
                    };

                    reviews.Add(review);
                }
            }

            // Add reviews to context and save
            await context.Reviews.AddRangeAsync(reviews);
            await context.SaveChangesAsync();

            Console.WriteLine($"Đã seed {reviews.Count} reviews thành công!");
        }
    }
}