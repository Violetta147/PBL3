// Data/Seeders/RestaurantCuisineSeeder.cs
using Microsoft.EntityFrameworkCore;
using PBL3.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.Data.Seeder
{
    public static class RestaurantCuisineSeeder
    {
        private static Random _random = new Random();

        public static async Task SeedAsync(ApplicationDbContext context)
        {
            if (await context.RestaurantCuisines.AnyAsync())
            {
                Console.WriteLine("RestaurantCuisines đã có dữ liệu. Bỏ qua seeding.");
                return;
            }

            var allRestaurants = await context.Restaurants.Include(r => r.Address).ToListAsync();
            var allCuisineTypes = await context.CuisineTypes.ToListAsync();

            if (!allRestaurants.Any() || !allCuisineTypes.Any())
            {
                Console.WriteLine("Không có đủ nhà hàng hoặc loại hình ẩm thực để seed RestaurantCuisines.");
                return;
            }

            var restaurantCuisinesToSeed = new List<RestaurantCuisine>();

            foreach (var restaurant in allRestaurants)
            {
                // SỬA Ở ĐÂY: Quyết định số lượng CuisineType cho mỗi nhà hàng (ví dụ: 1 đến 3)
                // Số lượng này sẽ là mục tiêu cuối cùng
                int targetNumberOfCuisines = _random.Next(1, 4); // Mỗi nhà hàng sẽ có từ 1 đến 3 CuisineTypes

                var cuisinesAssignedToThisRestaurant = new HashSet<int>();

                // Logic gợi ý CuisineType dựa trên tên hoặc đặc điểm nhà hàng
                var suggestedCuisineTypes = new List<CuisineType>();
                // (Giữ nguyên logic gợi ý của bạn ở đây, hoặc làm cho nó phức tạp hơn)
                if (restaurant.Name.Contains("Phở") || restaurant.Name.Contains("Madame Lân") || restaurant.Name.Contains("Bếp Trần") || restaurant.Name.Contains("Mỳ Quảng") || restaurant.Name.Contains("Cơm"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Ẩm thực Việt Nam"));
                if (restaurant.Name.Contains("Pizza") || restaurant.Name.Contains("Italia") || restaurant.Name.Contains("Pasta") || restaurant.Name.Contains("Refinery"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Ẩm thực Ý"));
                if (restaurant.Name.Contains("Hải Sản") || restaurant.Name.Contains("Seafood") || restaurant.Name.Contains("Bé Mặn"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Hải sản (Seafood)"));
                if (restaurant.Name.Contains("Sushi") || restaurant.Name.Contains("Ramen") || restaurant.Name.Contains("Nhật"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Ẩm thực Nhật Bản"));
                if (restaurant.Name.Contains("BBQ") || restaurant.Name.Contains("Kim Chi") || restaurant.Name.Contains("Nướng Lưới"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Ẩm thực Hàn Quốc"));
                if (restaurant.Name.Contains("Thái") || restaurant.Name.Contains("Tom Yum"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Ẩm thực Thái Lan"));
                if (restaurant.Name.Contains("Chay") || restaurant.Name.Contains("An Lạc"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Ăn chay (Vegetarian)"));
                if (restaurant.Name.Contains("Burger") || restaurant.Name.Contains("Fast Food"))
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Đồ ăn nhanh (Fast Food)"));
                if (restaurant.Name.Contains("Cộng Cafe")) // Ví dụ
                    suggestedCuisineTypes.Add(allCuisineTypes.FirstOrDefault(c => c.Name == "Trà sữa & Giải khát")); // Giả sử có CuisineType này


                // Thêm các CuisineType gợi ý trước, nhưng không vượt quá targetNumberOfCuisines
                foreach (var suggestedCuisine in suggestedCuisineTypes.Where(c => c != null))
                {
                    if (cuisinesAssignedToThisRestaurant.Count < targetNumberOfCuisines &&
                        !cuisinesAssignedToThisRestaurant.Contains(suggestedCuisine.Id))
                    {
                        restaurantCuisinesToSeed.Add(new RestaurantCuisine { RestaurantId = restaurant.Id, CuisineTypeId = suggestedCuisine.Id });
                        cuisinesAssignedToThisRestaurant.Add(suggestedCuisine.Id);
                    }
                }

                // Gán thêm ngẫu nhiên nếu chưa đủ số lượng mục tiêu
                while (cuisinesAssignedToThisRestaurant.Count < targetNumberOfCuisines && cuisinesAssignedToThisRestaurant.Count < allCuisineTypes.Count)
                {
                    CuisineType randomCuisineType;
                    do
                    {
                        randomCuisineType = allCuisineTypes[_random.Next(allCuisineTypes.Count)];
                    }
                    // Đảm bảo rằng CuisineType ngẫu nhiên này chưa được gán
                    while (cuisinesAssignedToThisRestaurant.Contains(randomCuisineType.Id));

                    restaurantCuisinesToSeed.Add(new RestaurantCuisine { RestaurantId = restaurant.Id, CuisineTypeId = randomCuisineType.Id });
                    cuisinesAssignedToThisRestaurant.Add(randomCuisineType.Id);
                }
            }

            if (restaurantCuisinesToSeed.Any())
            {
                await context.RestaurantCuisines.AddRangeAsync(restaurantCuisinesToSeed);
                await context.SaveChangesAsync();
                Console.WriteLine($"Đã gán CuisineTypes cho {allRestaurants.Count} nhà hàng (mỗi nhà hàng có thể có nhiều loại).");
            }
        }
    }
}