// Data/Seeders/MenuItemCategorySeeder.cs (Ví dụ cách 1 - Ít khuyến khích)
using Microsoft.EntityFrameworkCore;
using PBL3.Models;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace PBL3.Data.Seeder
{
    public static class MenuItemCategorySeeder
    {
        private static Random _random = new Random();

        public static async Task SeedAsync(ApplicationDbContext context)
        {
            // Đảm bảo MenuItem và Category đã được seed
            if (!await context.MenuItems.AnyAsync() || !await context.Categories.AnyAsync())
            {
                Console.WriteLine("Cần seed MenuItem và Category trước khi seed MenuItemCategory.");
                return;
            }

            // Kiểm tra xem MenuItemCategory đã có dữ liệu chưa
            if (await context.MenuItemCategories.AnyAsync())
            {
                Console.WriteLine("MenuItemCategories đã được seed trước đó.");
                return;
            }

            var allMenuItems = await context.MenuItems.ToListAsync();
            var allCategories = await context.Categories.ToListAsync();

            if (!allMenuItems.Any() || !allCategories.Any()) return;

            var menuItemCategoriesToSeed = new List<MenuItemCategory>();

            // LOGIC GÁN CATEGORY CHO TỪNG MENUITEM Ở ĐÂY SẼ RẤT PHỨC TẠP
            // Bạn phải quyết định mỗi MenuItem thuộc về những Category nào.
            // Ví dụ rất đơn giản và không thực tế:
            foreach (var menuItem in allMenuItems)
            {
                // Gán ngẫu nhiên 1-2 category cho mỗi món (không thông minh lắm)
                int numberOfCategories = _random.Next(1, 3);
                var assignedCategoriesForThisItem = new HashSet<int>();

                for (int i = 0; i < numberOfCategories; i++)
                {
                    if (assignedCategoriesForThisItem.Count >= allCategories.Count) break;

                    Category randomCategory;
                    do
                    {
                        randomCategory = allCategories[_random.Next(allCategories.Count)];
                    }
                    while (assignedCategoriesForThisItem.Contains(randomCategory.Id));

                    menuItemCategoriesToSeed.Add(new MenuItemCategory
                    {
                        MenuItemId = menuItem.Id,
                        CategoryId = randomCategory.Id
                    });
                    assignedCategoriesForThisItem.Add(randomCategory.Id);
                }
            }

            if (menuItemCategoriesToSeed.Any())
            {
                await context.MenuItemCategories.AddRangeAsync(menuItemCategoriesToSeed);
                await context.SaveChangesAsync();
                Console.WriteLine("Đã seed MenuItemCategories.");
            }
        }
    }
}