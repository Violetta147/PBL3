// Data/Seeders/RestaurantTagSeeder.cs
using Microsoft.EntityFrameworkCore;
using PBL3.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.Data.Seeder
{
    public static class RestaurantTagSeeder
    {
        private static Random _random = new Random();

        // Hàm SeedBasicTagsAsync (nếu bạn muốn giữ nó ở đây để đảm bảo tag tồn tại)
        public static async Task EnsureBasicTagsExistAsync(ApplicationDbContext context)
        {
            if (await context.Tags.AnyAsync())
            {
                return; // Tags đã tồn tại
            }
            // Sao chép logic từ TagSeeder.SeedBasicTagsAsync vào đây nếu cần
            // Hoặc gọi TagSeeder.SeedBasicTagsAsync(context); từ Program.cs trước seeder này.
            // Để đơn giản, giả sử TagSeeder.SeedBasicTagsAsync đã được gọi.
            if (!await context.Tags.AnyAsync())
            {
                Console.WriteLine("Cảnh báo: Không có Tags nào trong database. Hãy chạy TagSeeder.SeedBasicTagsAsync trước.");
                // Có thể gọi trực tiếp ở đây nếu TagSeeder là static và có hàm public
                // await TagSeeder.SeedBasicTagsAsync(context);
                // Hoặc throw exception
            }
        }


        public static async Task SeedAsync(ApplicationDbContext context)
        {
            // Đảm bảo Tag cơ bản đã được seed (nếu cần)
            // await EnsureBasicTagsExistAsync(context); // Bỏ comment nếu bạn muốn hàm này tự đảm bảo

            // Chỉ seed nếu bảng RestaurantTags chưa có dữ liệu
            if (await context.RestaurantTags.AnyAsync())
            {
                Console.WriteLine("RestaurantTags đã có dữ liệu. Bỏ qua seeding.");
                return;
            }

            var allRestaurants = await context.Restaurants.ToListAsync();
            var allTags = await context.Tags.ToListAsync();

            if (!allRestaurants.Any() || !allTags.Any())
            {
                Console.WriteLine("Không có đủ nhà hàng hoặc tags để seed RestaurantTags.");
                return;
            }

            var restaurantTagsToSeed = new List<RestaurantTag>();

            foreach (var restaurant in allRestaurants)
            {
                int numberOfTagsToAssign = _random.Next(3, 8); // Mỗi nhà hàng 3-7 tags
                var tagsAssignedToThisRestaurant = new HashSet<int>();

                for (int i = 0; i < numberOfTagsToAssign; i++)
                {
                    if (tagsAssignedToThisRestaurant.Count >= allTags.Count) break;

                    Tag randomTag;
                    do
                    {
                        randomTag = allTags[_random.Next(allTags.Count)];
                    }
                    while (tagsAssignedToThisRestaurant.Contains(randomTag.Id));

                    restaurantTagsToSeed.Add(new RestaurantTag { RestaurantId = restaurant.Id, TagId = randomTag.Id });
                    tagsAssignedToThisRestaurant.Add(randomTag.Id);
                }
            }

            if (restaurantTagsToSeed.Any())
            {
                await context.RestaurantTags.AddRangeAsync(restaurantTagsToSeed);
                await context.SaveChangesAsync();
                Console.WriteLine($"Đã gán Tags ngẫu nhiên cho {allRestaurants.Count} nhà hàng.");
            }
        }
    }
}