// Data/Seeders/CategorySeeder.cs
using Microsoft.EntityFrameworkCore;
using PBL3.Models;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic; // Cần cho List

namespace PBL3.Data.Seeder
{
    public static class CategorySeeder
    {
        public static async Task SeedAsync(ApplicationDbContext context)
        {
            if (await context.Categories.AnyAsync())
            {
                return; // Đã có dữ liệu
            }

            var now = DateTime.UtcNow;

            // --- TẠO VÀ LƯU CÁC CATEGORY CHA CHÍNH TRƯỚC ---
            var appetizersCategory = new Category { Name = "Món Khai Vị", IconUrl = "/images/category_icons/appetizer.png", CreatedAt = now, UpdatedAt = now };
            var mainCoursesCategory = new Category { Name = "Món Chính", IconUrl = "/images/category_icons/maincourse.png", CreatedAt = now, UpdatedAt = now };
            var dessertsCategory = new Category { Name = "Món Tráng Miệng", IconUrl = "/images/category_icons/dessert.png", CreatedAt = now, UpdatedAt = now };
            var drinksCategory = new Category { Name = "Đồ Uống", IconUrl = "/images/category_icons/drinks.png", CreatedAt = now, UpdatedAt = now };
            var snacksLightMealsCategory = new Category { Name = "Đồ Ăn Vặt & Ăn Nhẹ", IconUrl = "/images/category_icons/snacks.png", CreatedAt = now, UpdatedAt = now };
            var specificDishTypesCategory = new Category { Name = "Món Đặc Trưng & Theo Loại", IconUrl = "/images/category_icons/specific_dishes.png", CreatedAt = now, UpdatedAt = now };
            var bakeryCategory = new Category { Name = "Bánh Các Loại (Mặn & Ngọt)", IconUrl = "/images/category_icons/bakery.png", CreatedAt = now, UpdatedAt = now };
            var vegetarianCategoryMenu = new Category { Name = "Món Chay (Thực Đơn Chay)", IconUrl = "/images/category_icons/vegetarian_menu.png", CreatedAt = now, UpdatedAt = now };

            // Thêm các category cha chính vào context và LƯU để có Id
            await context.Categories.AddRangeAsync(
                appetizersCategory, mainCoursesCategory, dessertsCategory, drinksCategory,
                snacksLightMealsCategory, specificDishTypesCategory, bakeryCategory, vegetarianCategoryMenu
            );
            await context.SaveChangesAsync(); // QUAN TRỌNG: Lưu để các Id của category cha được tạo

            // --- TẠO CÁC CATEGORY CON VÀ CÁC CATEGORY CHA PHỤ (NẾU CÓ) ---
            // Những category này sẽ tham chiếu đến các category cha đã được lưu ở trên
            var childCategories = new List<Category>();

            // -- Con của Món Khai Vị --
            childCategories.Add(new Category { Name = "Gỏi & Salad", ParentCategoryId = appetizersCategory.Id, IconUrl = "/images/category_icons/salad.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Súp Khai Vị", ParentCategoryId = appetizersCategory.Id, IconUrl = "/images/category_icons/soup.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Món Cuốn (Khai Vị)", ParentCategoryId = appetizersCategory.Id, IconUrl = "/images/category_icons/rolls_appetizer.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Đồ Chiên (Khai Vị)", ParentCategoryId = appetizersCategory.Id, IconUrl = "/images/category_icons/fried_appetizer.png", CreatedAt = now, UpdatedAt = now });

            // -- Con của Món Chính --
            childCategories.Add(new Category { Name = "Món Thịt (Heo, Bò, Gà,...)", ParentCategoryId = mainCoursesCategory.Id, IconUrl = "/images/category_icons/meat_main.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Món Cá & Hải Sản Chế Biến", ParentCategoryId = mainCoursesCategory.Id, IconUrl = "/images/category_icons/seafood_main.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Món Rau (Xào, Luộc, Hấp)", ParentCategoryId = mainCoursesCategory.Id, IconUrl = "/images/category_icons/vegetable_main.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Món Kho & Hầm (Món Chính)", ParentCategoryId = mainCoursesCategory.Id, IconUrl = "/images/category_icons/stew_main.png", CreatedAt = now, UpdatedAt = now });

            // -- Con của Món Tráng Miệng --
            childCategories.Add(new Category { Name = "Chè Các Loại", ParentCategoryId = dessertsCategory.Id, IconUrl = "/images/category_icons/che.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bánh Ngọt (Tráng Miệng)", ParentCategoryId = dessertsCategory.Id, IconUrl = "/images/category_icons/cake_dessert.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Kem & Yogurt", ParentCategoryId = dessertsCategory.Id, IconUrl = "/images/category_icons/icecream_yogurt.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Trái Cây Tươi", ParentCategoryId = dessertsCategory.Id, IconUrl = "/images/category_icons/fruit_dessert.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bánh Flan & Rau Câu (Tráng Miệng)", ParentCategoryId = dessertsCategory.Id, IconUrl = "/images/category_icons/flan_jelly.png", CreatedAt = now, UpdatedAt = now });

            // -- Con của Đồ Uống --
            childCategories.Add(new Category { Name = "Nước Ngọt & Nước Có Ga", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/softdrink.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Nước Ép & Sinh Tố", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/juice_smoothie.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Trà Các Loại (Pha Chế)", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/tea_drinks.png", CreatedAt = now, UpdatedAt = now }); // Phân biệt với "Trà & Cà Phê" có thể là nguyên liệu
            childCategories.Add(new Category { Name = "Cà Phê (Pha Chế)", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/coffee_drinks.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bia Các Loại", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/beer.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Rượu Vang & Rượu Khác", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/wine.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cocktail & Mocktail", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/cocktail.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Sữa & Thức Uống Từ Sữa", ParentCategoryId = drinksCategory.Id, IconUrl = "/images/category_icons/milk_drinks.png", CreatedAt = now, UpdatedAt = now });

            // -- Con của Đồ Ăn Vặt & Ăn Nhẹ --
            childCategories.Add(new Category { Name = "Đồ Chiên Rán (Ăn Vặt)", ParentCategoryId = snacksLightMealsCategory.Id, IconUrl = "/images/category_icons/fried_snacks.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bánh Tráng Các Loại (Ăn Vặt)", ParentCategoryId = snacksLightMealsCategory.Id, IconUrl = "/images/category_icons/ricepaper_snacks.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Xiên Que (Ăn Vặt)", ParentCategoryId = snacksLightMealsCategory.Id, IconUrl = "/images/category_icons/skewers_snacks.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Nem Các Loại (Ăn Vặt)", ParentCategoryId = snacksLightMealsCategory.Id, IconUrl = "/images/category_icons/nem_snacks.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Ốc & Hải Sản Nhỏ (Ăn Vặt)", ParentCategoryId = snacksLightMealsCategory.Id, IconUrl = "/images/category_icons/shellfish_snacks.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Fast Food (Phần Nhỏ/Ăn Vặt)", ParentCategoryId = snacksLightMealsCategory.Id, IconUrl = "/images/category_icons/fastfood_snacks.png", CreatedAt = now, UpdatedAt = now });

            // -- Con của Món Đặc Trưng & Theo Loại (Đây là các category cha cấp 2) --
            // Chúng ta cần thêm những category cha này vào context và lưu trước khi thêm con của chúng
            var comCategory = new Category { Name = "Cơm Các Loại", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/rice_dishes.png", CreatedAt = now, UpdatedAt = now };
            var bunPhoMiCategory = new Category { Name = "Bún/Phở/Mì/Miến/Hủ Tiếu", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/noodles_soups.png", CreatedAt = now, UpdatedAt = now };
            var lauCategory = new Category { Name = "Lẩu Các Loại", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/hotpot.png", CreatedAt = now, UpdatedAt = now };
            var nuongCategory = new Category { Name = "Đồ Nướng & BBQ (Theo Loại)", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/bbq_grill_type.png", CreatedAt = now, UpdatedAt = now };
            var banhMiKepCategory = new Category { Name = "Bánh Mì Kẹp & Sandwich", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/banhmi_sandwich_type.png", CreatedAt = now, UpdatedAt = now };
            var xoiCategory = new Category { Name = "Xôi Các Loại", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/xoi_type.png", CreatedAt = now, UpdatedAt = now };
            var pizzaCategory = new Category { Name = "Pizza (Theo Loại)", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/pizza_type.png", CreatedAt = now, UpdatedAt = now }; // Phân biệt với CuisineType Pizza
            var monNhatCategory = new Category { Name = "Món Nhật (Sushi, Sashimi,...)", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/japanese_dishes.png", CreatedAt = now, UpdatedAt = now };
            var monHanCategory = new Category { Name = "Món Hàn (Kimbap, Tokbokki,...)", ParentCategoryId = specificDishTypesCategory.Id, IconUrl = "/images/category_icons/korean_dishes.png", CreatedAt = now, UpdatedAt = now };


            await context.Categories.AddRangeAsync(comCategory, bunPhoMiCategory, lauCategory, nuongCategory, banhMiKepCategory, xoiCategory, pizzaCategory, monNhatCategory, monHanCategory);
            await context.SaveChangesAsync(); // Lưu các category cha cấp 2

            // ---- Con của Cơm Các Loại ----
            childCategories.Add(new Category { Name = "Cơm Tấm", ParentCategoryId = comCategory.Id, IconUrl = "/images/category_icons/com_tam.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cơm Gà (Xối Mỡ, Hội An,...)", ParentCategoryId = comCategory.Id, IconUrl = "/images/category_icons/com_ga.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cơm Sườn (Nướng, Bì, Chả)", ParentCategoryId = comCategory.Id, IconUrl = "/images/category_icons/com_suon.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cơm Rang/Chiên", ParentCategoryId = comCategory.Id, IconUrl = "/images/category_icons/fried_rice.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cơm Phần/Văn Phòng", ParentCategoryId = comCategory.Id, IconUrl = "/images/category_icons/office_lunch.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cơm Chay (Phần)", ParentCategoryId = comCategory.Id, IconUrl = "/images/category_icons/veg_rice_set.png", CreatedAt = now, UpdatedAt = now });


            // ---- Con của Bún/Phở/Mì/Miến/Hủ Tiếu ----
            childCategories.Add(new Category { Name = "Phở (Bò, Gà)", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/pho.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bún Bò Huế", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/bun_bo_hue.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bún Chả Hà Nội", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/bun_cha_hanoi.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bún Riêu Cua & Ốc", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/bun_rieu.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bún Đậu Mắm Tôm", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/bun_dau.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Mì Quảng (Tôm Thịt, Gà, Ếch)", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/mi_quang.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Hủ Tiếu (Nam Vang, Mực, Xương)", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/hu_tieu.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Mì Ý (Spaghetti, Pasta Khác)", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/pasta.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Ramen & Udon (Nhật Bản)", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/ramen_udon.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Miến Lươn & Miến Gà", ParentCategoryId = bunPhoMiCategory.Id, IconUrl = "/images/category_icons/mien.png", CreatedAt = now, UpdatedAt = now });

            // ---- Con của Lẩu Các Loại ----
            childCategories.Add(new Category { Name = "Lẩu Thái (Chua Cay)", ParentCategoryId = lauCategory.Id, IconUrl = "/images/category_icons/thai_hotpot.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Lẩu Hải Sản (Thập Cẩm, Riêu Cua)", ParentCategoryId = lauCategory.Id, IconUrl = "/images/category_icons/seafood_hotpot.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Lẩu Bò (Nhúng Dấm, Thường)", ParentCategoryId = lauCategory.Id, IconUrl = "/images/category_icons/beef_hotpot.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Lẩu Kim Chi (Hàn Quốc)", ParentCategoryId = lauCategory.Id, IconUrl = "/images/category_icons/kimchi_hotpot.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Lẩu Nấm (Chay, Mặn)", ParentCategoryId = lauCategory.Id, IconUrl = "/images/category_icons/mushroom_hotpot.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Lẩu Gà Lá É", ParentCategoryId = lauCategory.Id, IconUrl = "/images/category_icons/chicken_hotpot_la_e.png", CreatedAt = now, UpdatedAt = now });


            // ---- Con của Đồ Nướng & BBQ (Theo Loại) ----
            childCategories.Add(new Category { Name = "Thịt Nướng (Ba Chỉ, Sườn, Bò Mỹ)", ParentCategoryId = nuongCategory.Id, IconUrl = "/images/category_icons/grilled_meat_type.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Hải Sản Nướng (Tôm, Mực, Cá)", ParentCategoryId = nuongCategory.Id, IconUrl = "/images/category_icons/grilled_seafood_type.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Gà Nướng (Nguyên Con, Cánh, Đùi)", ParentCategoryId = nuongCategory.Id, IconUrl = "/images/category_icons/grilled_chicken_type.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Xiên Nướng Thập Cẩm", ParentCategoryId = nuongCategory.Id, IconUrl = "/images/category_icons/grilled_skewers_type.png", CreatedAt = now, UpdatedAt = now });


            // ---- Con của Bánh Mì Kẹp & Sandwich ----
            childCategories.Add(new Category { Name = "Bánh Mì Thịt Việt Nam (Đặc Ruột, Chả)", ParentCategoryId = banhMiKepCategory.Id, IconUrl = "/images/category_icons/banhmi_vn.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bánh Mì Chảo (Trứng, Pate, Xúc Xích)", ParentCategoryId = banhMiKepCategory.Id, IconUrl = "/images/category_icons/banhmi_chao.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Burger (Bò, Gà, Tôm)", ParentCategoryId = banhMiKepCategory.Id, IconUrl = "/images/category_icons/burger_type.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Sandwich Kẹp (Thịt Nguội, Phô Mai)", ParentCategoryId = banhMiKepCategory.Id, IconUrl = "/images/category_icons/sandwich.png", CreatedAt = now, UpdatedAt = now });

            // ---- Con của Xôi Các Loại ----
            childCategories.Add(new Category { Name = "Xôi Mặn (Thịt, Chả, Pate, Lạp Xưởng)", ParentCategoryId = xoiCategory.Id, IconUrl = "/images/category_icons/xoi_man.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Xôi Ngọt (Xôi Xoài, Xôi Gấc, Đậu Xanh)", ParentCategoryId = xoiCategory.Id, IconUrl = "/images/category_icons/xoi_ngot.png", CreatedAt = now, UpdatedAt = now });

            // ---- Con của Pizza (Theo Loại) ----
            childCategories.Add(new Category { Name = "Pizza Hải Sản", ParentCategoryId = pizzaCategory.Id, IconUrl = "/images/category_icons/pizza_seafood.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Pizza Thịt Nguội & Xúc Xích", ParentCategoryId = pizzaCategory.Id, IconUrl = "/images/category_icons/pizza_meatlover.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Pizza Phô Mai", ParentCategoryId = pizzaCategory.Id, IconUrl = "/images/category_icons/pizza_cheese.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Pizza Chay (Rau Củ)", ParentCategoryId = pizzaCategory.Id, IconUrl = "/images/category_icons/pizza_vegetarian.png", CreatedAt = now, UpdatedAt = now });


            // ---- Con của Món Nhật ----
            childCategories.Add(new Category { Name = "Sushi & Maki", ParentCategoryId = monNhatCategory.Id, IconUrl = "/images/category_icons/sushi_maki.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Sashimi (Cá Hồi, Cá Ngừ,...)", ParentCategoryId = monNhatCategory.Id, IconUrl = "/images/category_icons/sashimi.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cơm Bento & Donburi", ParentCategoryId = monNhatCategory.Id, IconUrl = "/images/category_icons/bento_donburi.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Tempura (Tôm, Rau Củ)", ParentCategoryId = monNhatCategory.Id, IconUrl = "/images/category_icons/tempura.png", CreatedAt = now, UpdatedAt = now });

            // ---- Con của Món Hàn ----
            childCategories.Add(new Category { Name = "Kimbap (Cơm Cuộn)", ParentCategoryId = monHanCategory.Id, IconUrl = "/images/category_icons/kimbap.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Tokbokki & Mì Cay Hàn Quốc", ParentCategoryId = monHanCategory.Id, IconUrl = "/images/category_icons/tokbokki_spicy_noodles.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Cơm Trộn Bibimbap", ParentCategoryId = monHanCategory.Id, IconUrl = "/images/category_icons/bibimbap.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Gà Rán Kiểu Hàn", ParentCategoryId = monHanCategory.Id, IconUrl = "/images/category_icons/korean_fried_chicken.png", CreatedAt = now, UpdatedAt = now });


            // -- Con của Bánh Các Loại (Mặn & Ngọt) -- (Có thể là category cha cấp 2 hoặc con trực tiếp)
            childCategories.Add(new Category { Name = "Bánh Mì (Nguyên Ổ)", ParentCategoryId = bakeryCategory.Id, IconUrl = "/images/category_icons/bread_loaf.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bánh Ngọt (Bán Lẻ)", ParentCategoryId = bakeryCategory.Id, IconUrl = "/images/category_icons/pastries.png", CreatedAt = now, UpdatedAt = now }); // Croissant, Danish, Muffin
            childCategories.Add(new Category { Name = "Bánh Mặn (Bán Lẻ)", ParentCategoryId = bakeryCategory.Id, IconUrl = "/images/category_icons/savory_pastries.png", CreatedAt = now, UpdatedAt = now }); // Bánh bao, Pâté chaud
            childCategories.Add(new Category { Name = "Bánh Kem Sinh Nhật & Sự Kiện", ParentCategoryId = bakeryCategory.Id, IconUrl = "/images/category_icons/birthday_event_cake.png", CreatedAt = now, UpdatedAt = now });

            // -- Con của Món Chay (Thực Đơn Chay) --
            childCategories.Add(new Category { Name = "Cơm Chay (Theo Món)", ParentCategoryId = vegetarianCategoryMenu.Id, IconUrl = "/images/category_icons/veg_rice_dish.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Bún/Phở/Mì Chay (Theo Món)", ParentCategoryId = vegetarianCategoryMenu.Id, IconUrl = "/images/category_icons/veg_noodles_dish.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Lẩu Chay (Theo Món)", ParentCategoryId = vegetarianCategoryMenu.Id, IconUrl = "/images/category_icons/veg_hotpot_dish.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Món Xào Chay (Theo Món)", ParentCategoryId = vegetarianCategoryMenu.Id, IconUrl = "/images/category_icons/veg_stirfry_dish.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Khai Vị Chay (Theo Món)", ParentCategoryId = vegetarianCategoryMenu.Id, IconUrl = "/images/category_icons/veg_appetizer_dish.png", CreatedAt = now, UpdatedAt = now });
            childCategories.Add(new Category { Name = "Gỏi & Salad Chay", ParentCategoryId = vegetarianCategoryMenu.Id, IconUrl = "/images/category_icons/veg_salad.png", CreatedAt = now, UpdatedAt = now });


            // Thêm tất cả các category con đã tạo vào context
            if (childCategories.Any())
            {
                await context.Categories.AddRangeAsync(childCategories);
                await context.SaveChangesAsync();
            }
            Console.WriteLine("Đã seed xong Categories (cha và con).");
        }
    }
}