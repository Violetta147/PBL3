// Data/Seeders/MenuSeeder.cs
using Microsoft.EntityFrameworkCore;
using PBL3.Models; // Đảm bảo namespace này đúng
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace PBL3.Data.Seeder
{
    public static class MenuSeeder
    {
        private static Random _random = new Random();

        public static async Task SeedAsync(ApplicationDbContext context)
        {
            if (await context.Menus.AnyAsync())
            {
                Console.WriteLine("Menus đã được seed trước đó.");
                return;
            }

            var allRestaurants = await context.Restaurants.Include(r => r.Address).ToListAsync();
            if (!allRestaurants.Any())
            {
                Console.WriteLine("Không có nhà hàng nào để seed menu. Hãy chạy RestaurantSeeder trước.");
                return;
            }

            // Lấy TẤT CẢ category một lần, bao gồm cả ParentCategory để có thể query theo tên cha
            var allCategories = await context.Categories.Include(c => c.ParentCategory).ToListAsync();
            if (!allCategories.Any())
            {
                Console.WriteLine("Không có category nào để seed menu item. Hãy chạy CategorySeeder trước.");
                return;
            }

            // Helper để lấy CategoryId theo tên và tên category cha (nếu có)
            // Điều này quan trọng vì nhiều category con có thể có tên giống nhau nhưng khác cha
            Func<string, string, int?> getCategoryId = (categoryName, parentCategoryName) =>
            {
                Category category = null;
                if (!string.IsNullOrEmpty(parentCategoryName))
                {
                    // Tìm category con dựa trên tên của nó VÀ tên của category cha
                    category = allCategories.FirstOrDefault(c =>
                        c.Name.Equals(categoryName, StringComparison.OrdinalIgnoreCase) &&
                        c.ParentCategory != null &&
                        c.ParentCategory.Name.Equals(parentCategoryName, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    // Tìm category cha (không có parent)
                    category = allCategories.FirstOrDefault(c =>
                        c.Name.Equals(categoryName, StringComparison.OrdinalIgnoreCase) &&
                        c.ParentCategoryId == null);
                }
                if (category == null)
                {
                    //Console.WriteLine($"CẢNH BÁO: Không tìm thấy Category '{categoryName}' (Cha: '{parentCategoryName ?? "Không có"}')");
                }
                return category?.Id;
            };


            var menusToSeed = new List<Menu>();
            var now = DateTime.UtcNow;

            foreach (var restaurant in allRestaurants)
            {
                Console.WriteLine($"Đang seed menu cho nhà hàng: {restaurant.Name}");
                var menu = new Menu
                {
                    RestaurantId = restaurant.Id,
                    Title = $"Thực Đơn Chính - {restaurant.Name}",
                    Description = $"Khám phá các món ăn đặc sắc tại {restaurant.Name}",
                    IsActive = true,
                    DisplayOrder = 1,
                    CreatedAt = now,
                    UpdatedAt = now,
                    MenuSections = new List<MenuSection>()
                };

                // --- Menu cho Madame Lân - Đặc Sản Đà Thành ---
                if (restaurant.Name.Contains("Madame Lân"))
                {
                    var khaiViSection = AddSection(menu, "Món Khai Vị Đặc Sắc", 1);
                    AddItem(khaiViSection, restaurant.Id, "Gỏi Cuốn Tôm Thịt Madame Lân", "Gỏi cuốn tươi ngon với tôm, thịt, bún và rau sống, nước chấm đặc biệt.", 65000m, new List<int?> { getCategoryId("Gỏi & Salad", "Món Khai Vị"), getCategoryId("Món Cuốn (Khai Vị)", "Món Khai Vị") });
                    AddItem(khaiViSection, restaurant.Id, "Chả Ram Tôm Đất Giòn Tan", "Chả ram giòn rụm, nhân tôm đất tươi ngọt, đậm đà.", 75000m, new List<int?> { getCategoryId("Đồ Chiên (Khai Vị)", "Món Khai Vị") });

                    var monChinhSection = AddSection(menu, "Đặc Sản Xứ Quảng Nổi Tiếng", 2);
                    AddItem(monChinhSection, restaurant.Id, "Mì Quảng Gà Ta Đặc Biệt", "Mì Quảng truyền thống với thịt gà ta thả vườn dai ngon, nước dùng đậm vị.", 70000m, new List<int?> { getCategoryId("Mì Quảng (Tôm Thịt, Gà, Ếch)", "Bún/Phở/Mì/Miến/Hủ Tiếu"), getCategoryId("Món Chính", null) });
                    AddItem(monChinhSection, restaurant.Id, "Bánh Xèo Tôm Nhảy Truyền Thống", "Bánh xèo vỏ giòn tan, nhân tôm nhảy tươi rói, giá đỗ.", 85000m, new List<int?> { getCategoryId("Bánh Các Loại (Mặn & Ngọt)", null), getCategoryId("Món Chính", null) }); // Cần category "Bánh Xèo" cụ thể nếu có
                    AddItem(monChinhSection, restaurant.Id, "Nem Lụi Nướng Sả Thơm Lừng", "Nem lụi làm từ thịt heo tươi, quấn sả, nướng trên than hồng, ăn kèm rau sống và bánh tráng.", 90000m, new List<int?> { getCategoryId("Thịt Nướng (Ba Chỉ, Sườn, Bò Mỹ)", "Đồ Nướng & BBQ (Theo Loại)"), getCategoryId("Món Thịt (Heo, Bò, Gà,...)", "Món Chính") });

                    var doUongSection = AddSection(menu, "Giải Khát Thanh Nhiệt", 3);
                    AddDrinksToSection(doUongSection, restaurant.Id, allCategories, getCategoryId, includeJuiceSmoothie: true);
                }
                // --- Menu cho Hải Sản Bé Mặn ---
                else if (restaurant.Name.Contains("Hải Sản Bé Mặn"))
                {
                    var haiSanTuoiSongSection = AddSection(menu, "Hải Sản Tươi Bắt Tại Hồ", 1);
                    AddItem(haiSanTuoiSongSection, restaurant.Id, "Tôm Hùm Alaska Nướng Phô Mai Béo Ngậy", "Tôm hùm Alaska tươi sống size lớn, nướng phô mai Mozzarella.", 1250000m, new List<int?> { getCategoryId("Món Cá & Hải Sản Chế Biến", "Món Chính"), getCategoryId("Hải Sản Nướng (Tôm, Mực, Cá)", "Đồ Nướng & BBQ (Theo Loại)") });
                    AddItem(haiSanTuoiSongSection, restaurant.Id, "Cua Gạch Cà Mau Rang Me Chua Ngọt", "Cua gạch chắc thịt, đầy gạch son, sốt me chua ngọt đậm đà.", 480000m, new List<int?> { getCategoryId("Món Cá & Hải Sản Chế Biến", "Món Chính") });
                    AddItem(haiSanTuoiSongSection, restaurant.Id, "Mực Lá Đại Dương Nướng Sa Tế Cay Nồng", "Mực lá tươi giòn, dày mình, nướng sa tế cay thơm.", 280000m, new List<int?> { getCategoryId("Hải Sản Nướng (Tôm, Mực, Cá)", "Đồ Nướng & BBQ (Theo Loại)"), getCategoryId("Món Cá & Hải Sản Chế Biến", "Món Chính") });
                    AddItem(haiSanTuoiSongSection, restaurant.Id, "Ốc Hương Thiên Nhiên Hấp Sả Thái", "Ốc hương tươi, size lớn, hấp sả kiểu Thái.", 220000m, new List<int?> { getCategoryId("Ốc & Hải Sản Nhỏ (Ăn Vặt)", "Đồ Ăn Vặt & Ăn Nhẹ"), getCategoryId("Món Cá & Hải Sản Chế Biến", "Món Chính") });

                    var lauHaiSanSection = AddSection(menu, "Lẩu Hải Sản Đặc Biệt", 2);
                    AddItem(lauHaiSanSection, restaurant.Id, "Lẩu Hải Sản Chua Cay Kiểu Thái Bé Mặn", "Nước lẩu Tomyum chua cay chuẩn vị, đầy ắp hải sản tươi: tôm, cua, mực, nghêu.", 380000m, new List<int?> { getCategoryId("Lẩu Thái (Chua Cay)", "Lẩu Các Loại"), getCategoryId("Lẩu Hải Sản (Thập Cẩm, Riêu Cua)", "Lẩu Các Loại") });
                    AddItem(lauHaiSanSection, restaurant.Id, "Lẩu Cua Bầu", "Lẩu cua đồng nấu bầu thanh mát, ngọt vị.", 320000m, new List<int?> { getCategoryId("Lẩu Hải Sản (Thập Cẩm, Riêu Cua)", "Lẩu Các Loại") });


                    var doUongSection = AddSection(menu, "Đồ Uống Các Loại", 3);
                    AddDrinksToSection(doUongSection, restaurant.Id, allCategories, getCategoryId, includeBeer: true, includeWine: true);
                }
                // --- Menu cho Bếp Trần ---
                else if (restaurant.Name.Contains("Bếp Trần"))
                {
                    var dacSanSection = AddSection(menu, "Đặc Sản Bếp Trần Không Thể Bỏ Qua", 1);
                    AddItem(dacSanSection, restaurant.Id, "Bánh Tráng Cuốn Thịt Heo Hai Đầu Da", "Thịt heo luộc hai đầu da mềm ngọt, cuốn bánh tráng phơi sương, rau sống tươi ngon, chấm mắm nêm công thức riêng.", 125000m, new List<int?> { getCategoryId("Món Cuốn (Khai Vị)", "Món Khai Vị"), getCategoryId("Món Chính", null) });
                    AddItem(dacSanSection, restaurant.Id, "Bún Mắm Nêm Thịt Heo Quay Giòn Bì", "Bún tươi, thịt heo quay da giòn rụm, chả bò, nem chua, rau sống, chan mắm nêm đậm đà.", 75000m, new List<int?> { getCategoryId("Bún/Phở/Mì/Miến/Hủ Tiếu", "Món Đặc Trưng & Theo Loại") }); // Cần Category "Bún Mắm"
                    AddItem(dacSanSection, restaurant.Id, "Mì Quảng Ếch Đồng Đặc Biệt", "Sợi mì Quảng vàng óng, thịt ếch đồng dai ngon thấm vị, nước dùng đậm đà.", 85000m, new List<int?> { getCategoryId("Mì Quảng (Tôm Thịt, Gà, Ếch)", "Bún/Phở/Mì/Miến/Hủ Tiếu") });
                    AddItem(dacSanSection, restaurant.Id, "Cao Lầu Hội An", "Sợi mì cao lầu dai đặc trưng, thịt xá xíu, tóp mỡ, rau sống.", 70000m, new List<int?> { getCategoryId("Bún/Phở/Mì/Miến/Hủ Tiếu", "Món Đặc Trưng & Theo Loại") }); // Cần Category "Cao Lầu"

                    var monThemSection = AddSection(menu, "Món Ăn Kèm & Tráng Miệng", 2);
                    AddItem(monThemSection, restaurant.Id, "Ram Cuốn Cải Chấm Tương Đậu", "Ram chiên giòn tan cuốn rau cải tươi mát, chấm nước tương đậu phộng.", 55000m, new List<int?> { getCategoryId("Món Cuốn (Khai Vị)", "Món Khai Vị"), getCategoryId("Đồ Chiên (Khai Vị)", "Món Khai Vị") });
                    AddItem(monThemSection, restaurant.Id, "Chè Đậu Xanh Nha Đam Hạt Sen", "Chè đậu xanh thanh mát, nha đam giòn, hạt sen bùi.", 35000m, new List<int?> { getCategoryId("Chè Các Loại", "Món Tráng Miệng") });

                    var doUongSection = AddSection(menu, "Nước Giải Khát Truyền Thống", 3);
                    AddDrinksToSection(doUongSection, restaurant.Id, allCategories, getCategoryId, includeJuiceSmoothie: true);
                }
                // --- Menu cho Pizza 4P's ---
                else if (restaurant.Name.Contains("Pizza 4P's"))
                {
                    var pizzaSignatureSection = AddSection(menu, "Pizza Nhà Làm Đặc Biệt (Signature)", 1);
                    AddItem(pizzaSignatureSection, restaurant.Id, "Pizza Burrata Parma Ham", "Pizza đế mỏng với phô mai Burrata tươi, Prosciutto di Parma, rocket và cà chua bi.", 340000m, new List<int?> { getCategoryId("Pizza Thịt Nguội & Xúc Xích", "Pizza (Theo Loại)"), getCategoryId("Món Chính", null) });
                    AddItem(pizzaSignatureSection, restaurant.Id, "Pizza 4 Cheese (Four Cheese)", "Kết hợp 4 loại phô mai hảo hạng: Mozzarella, Parmesan, Gorgonzola, Camembert.", 290000m, new List<int?> { getCategoryId("Pizza Phô Mai", "Pizza (Theo Loại)") });
                    AddItem(pizzaSignatureSection, restaurant.Id, "Pizza Teriyaki Chicken & Seaweed", "Pizza gà sốt Teriyaki, rong biển, mè rang, hành lá kiểu Nhật.", 280000m, new List<int?> { getCategoryId("Pizza (Theo Loại)", "Món Đặc Trưng & Theo Loại") }); // Cần category "Pizza Gà"

                    var pastaHandmadeSection = AddSection(menu, "Pasta Tươi Nhà Làm & Mì Ý", 2);
                    AddItem(pastaHandmadeSection, restaurant.Id, "Crab Tomato Cream Spaghetti with Ricotta Cheese", "Mì Ý cua sốt kem cà chua với phô mai Ricotta.", 260000m, new List<int?> { getCategoryId("Mì Ý (Spaghetti, Pasta Khác)", "Bún/Phở/Mì/Miến/Hủ Tiếu") });
                    AddItem(pastaHandmadeSection, restaurant.Id, "House-made Cheese Fondue", "Lẩu phô mai nhà làm ăn kèm bánh mì, xúc xích, rau củ.", 350000m, new List<int?> { getCategoryId("Món Khai Vị", null), getCategoryId("Món Chính", null) }); // Cần Category "Fondue"

                    var appetSaladDessertSection = AddSection(menu, "Khai Vị, Salad & Tráng Miệng", 3);
                    AddItem(appetSaladDessertSection, restaurant.Id, "Rocket Salad with Balsamic Dressing", "Salad rau rocket với cà chua bi, phô mai Parmesan và sốt dầu giấm Balsamic.", 150000m, new List<int?> { getCategoryId("Gỏi & Salad", "Món Khai Vị") });
                    AddItem(appetSaladDessertSection, restaurant.Id, "Tiramisu Classic", "Bánh Tiramisu cổ điển Ý.", 110000m, new List<int?> { getCategoryId("Bánh Ngọt (Tráng Miệng)", "Món Tráng Miệng") });

                    var drinksCreativeSection = AddSection(menu, "Đồ Uống Sáng Tạo & Rượu Vang", 4);
                    AddDrinksToSection(drinksCreativeSection, restaurant.Id, allCategories, getCategoryId, includeJuiceSmoothie: true, includeWine: true, includeCocktail: true);
                }
                // --- Menu mặc định cho các nhà hàng còn lại ---
                else
                {
                    var defaultKhaiVi = AddSection(menu, "Món Khai Vị Tổng Hợp", 1);
                    AddItem(defaultKhaiVi, restaurant.Id, "Gỏi Xoài Tôm Thịt", "Gỏi xoài xanh chua ngọt với tôm, thịt ba chỉ.", 70000m, new List<int?> { getCategoryId("Gỏi & Salad", "Món Khai Vị") });
                    AddItem(defaultKhaiVi, restaurant.Id, "Nem Chua Rán Hà Nội", "Nem chua rán giòn, chấm tương ớt.", 60000m, new List<int?> { getCategoryId("Đồ Chiên (Khai Vị)", "Món Khai Vị"), getCategoryId("Nem Các Loại (Ăn Vặt)", "Đồ Ăn Vặt & Ăn Nhẹ") });


                    var defaultMonChinh = AddSection(menu, "Món Chính Đa Dạng", 2);
                    AddItem(defaultMonChinh, restaurant.Id, "Bò Lúc Lắc Khoai Tây Chiên", "Thịt bò mềm xào lúc lắc, ăn kèm khoai tây chiên.", 150000m, new List<int?> { getCategoryId("Món Thịt (Heo, Bò, Gà,...)", "Món Chính") });
                    AddItem(defaultMonChinh, restaurant.Id, "Gà Ta Quay Lu Da Giòn", "Gà ta nguyên con quay lu, da vàng giòn, thịt mềm ngọt.", 350000m, new List<int?> { getCategoryId("Gà Nướng (Nguyên Con, Cánh, Đùi)", "Đồ Nướng & BBQ (Theo Loại)"), getCategoryId("Món Thịt (Heo, Bò, Gà,...)", "Món Chính") });
                    AddItem(defaultMonChinh, restaurant.Id, "Canh Chua Cá Lóc Miền Tây", "Canh chua cá lóc đậm đà hương vị miền Tây.", 120000m, new List<int?> { getCategoryId("Súp Khai Vị", "Món Khai Vị"), getCategoryId("Món Cá & Hải Sản Chế Biến", "Món Chính") }); // Canh cũng có thể là món chính


                    var defaultTrangMieng = AddSection(menu, "Tráng Miệng Ngọt Ngào", 3);
                    AddItem(defaultTrangMieng, restaurant.Id, "Trái Cây Theo Mùa", "Đĩa trái cây tươi theo mùa.", 50000m, new List<int?> { getCategoryId("Trái Cây Tươi", "Món Tráng Miệng") });
                    AddItem(defaultTrangMieng, restaurant.Id, "Sữa Chua Nếp Cẩm", "Sữa chua sánh mịn ăn kèm nếp cẩm dẻo thơm.", 35000m, new List<int?> { getCategoryId("Kem & Yogurt", "Món Tráng Miệng") });

                    var defaultDoUong = AddSection(menu, "Đồ Uống Phổ Biến", 4);
                    AddDrinksToSection(defaultDoUong, restaurant.Id, allCategories, getCategoryId, includeJuiceSmoothie: true, includeBeer: true);
                }


                if (menu.MenuSections.Any(ms => ms.MenuItems.Any())) // Chỉ thêm menu nếu có ít nhất 1 món ăn
                {
                    menusToSeed.Add(menu);
                }
                else
                {
                    Console.WriteLine($"WARNING: Menu cho nhà hàng '{restaurant.Name}' không có món ăn nào được thêm.");
                }
            }


            if (menusToSeed.Any())
            {
                await context.Menus.AddRangeAsync(menusToSeed);
                await context.SaveChangesAsync();
                Console.WriteLine("Đã seed xong Menus, MenuSections, MenuItems, và MenuItemCategories.");
            }
            else
            {
                Console.WriteLine("Không có menu nào được tạo để seed.");
            }
        }

        private static MenuSection AddSection(Menu menu, string title, int displayOrder)
        {
            var section = new MenuSection
            {
                // MenuId sẽ được EF Core tự động gán khi SaveChanges nếu section được thêm vào menu.MenuSections
                Title = title,
                DisplayOrder = displayOrder,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                MenuItems = new List<MenuItem>()
            };
            menu.MenuSections.Add(section);
            return section;
        }

        private static void AddItem(MenuSection section, int restaurantId, string name, string description, decimal price, List<int?> categoryIds, string imageUrl = null, bool isAvailable = true)
        {
            // EF Core sẽ tự động gán MenuId cho section khi nó được thêm vào menu.MenuSections và menu được lưu.
            // Sau đó, khi MenuItem được thêm vào section.MenuItems và section được lưu (như một phần của menu),
            // EF Core cũng sẽ tự động quản lý MenuSectionId cho MenuItem nếu mối quan hệ được thiết lập đúng.
            // Tuy nhiên, để chắc chắn, bạn có thể gán section.Menu.Id cho menuItem.MenuId nếu section đã có MenuId.

            var menuItem = new MenuItem
            {
                RestaurantId = restaurantId,
                Name = name,
                Description = description,
                Price = price,
                IsAvailable = isAvailable,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                MenuItemCategories = new List<MenuItemCategory>()
            };

            // Gán MenuSection cho MenuItem để EF Core biết (hoặc nó sẽ tự suy ra nếu MenuItem được thêm vào section.MenuItems)
            // menuItem.MenuSection = section; // Hoặc gán MenuSectionId nếu bạn có Id ngay

            foreach (var categoryId in categoryIds.Where(id => id.HasValue))
            {
                menuItem.MenuItemCategories.Add(new MenuItemCategory { CategoryId = categoryId.Value });
            }
            section.MenuItems.Add(menuItem);
        }

        private static void AddDrinksToSection(MenuSection section, int restaurantId, List<Category> allCategories, Func<string, string, int?> getCatId, bool includeBeer = false, bool includeWine = false, bool includeJuiceSmoothie = false, bool includeCocktail = false)
        {
            var catDoUong = getCatId("Đồ Uống", null);
            var catNuocNgot = getCatId("Nước Ngọt & Nước Có Ga", "Đồ Uống");
            var catTra = getCatId("Trà Các Loại (Pha Chế)", "Đồ Uống");
            var catCafe = getCatId("Cà Phê (Pha Chế)", "Đồ Uống");
            var catNuocEp = getCatId("Nước Ép & Sinh Tố", "Đồ Uống");
            var catBia = getCatId("Bia Các Loại", "Đồ Uống");
            var catRuouVang = getCatId("Rượu Vang & Rượu Khác", "Đồ Uống");
            var catCocktail = getCatId("Cocktail & Mocktail", "Đồ Uống");

            if (catNuocNgot.HasValue)
            {
                AddItem(section, restaurantId, "Coca-Cola", "Nước ngọt Coca-Cola lon 330ml", 20000m, new List<int?> { catDoUong, catNuocNgot });
                AddItem(section, restaurantId, "Pepsi Light", "Nước ngọt Pepsi không đường", 22000m, new List<int?> { catDoUong, catNuocNgot });
                AddItem(section, restaurantId, "Sprite Chanh", "Nước ngọt Sprite vị chanh", 20000m, new List<int?> { catDoUong, catNuocNgot });
                AddItem(section, restaurantId, "Nước Suối Lavie", "Nước suối tinh khiết 500ml", 15000m, new List<int?> { catDoUong, catNuocNgot });
            }
            if (catTra.HasValue)
            {
                AddItem(section, restaurantId, "Trà Chanh Vỉa Hè", "Trà chanh chua ngọt mát lạnh", 25000m, new List<int?> { catDoUong, catTra });
                AddItem(section, restaurantId, "Trà Đào Cam Sả Nhiệt Đới", "Trà đào kết hợp cam tươi và sả cây", 40000m, new List<int?> { catDoUong, catTra });
                AddItem(section, restaurantId, "Trà Oolong Túi Lọc", "Trà oolong túi lọc nóng/đá", 30000m, new List<int?> { catDoUong, catTra });
            }
            if (catCafe.HasValue)
            {
                AddItem(section, restaurantId, "Cà Phê Đen Đá Truyền Thống", "Cà phê rang xay nguyên chất, pha phin", 30000m, new List<int?> { catDoUong, catCafe });
                AddItem(section, restaurantId, "Cà Phê Sữa Đá Sài Gòn", "Cà phê sữa đá đậm đà hương vị Sài Gòn", 35000m, new List<int?> { catDoUong, catCafe });
                AddItem(section, restaurantId, "Bạc Xỉu Nóng", "Bạc xỉu (sữa nhiều hơn cà phê) nóng", 40000m, new List<int?> { catDoUong, catCafe });

            }

            if (includeJuiceSmoothie && catNuocEp.HasValue)
            {
                AddItem(section, restaurantId, "Nước Ép Cam Nguyên Chất", "Cam tươi vắt không đường, không đá (tùy chọn)", 45000m, new List<int?> { catDoUong, catNuocEp });
                AddItem(section, restaurantId, "Sinh Tố Bơ Sáp", "Bơ sáp Đắk Lắk xay mịn béo ngậy", 50000m, new List<int?> { catDoUong, catNuocEp });
                AddItem(section, restaurantId, "Nước Chanh Dây Tươi", "Chanh dây tươi chua ngọt", 35000m, new List<int?> { catDoUong, catNuocEp });
            }
            if (includeBeer && catBia.HasValue)
            {
                AddItem(section, restaurantId, "Bia Tiger Crystal Chai", "Bia Tiger Crystal chai 330ml", 35000m, new List<int?> { catDoUong, catBia });
                AddItem(section, restaurantId, "Bia Heineken Silver Lon", "Bia Heineken Silver lon 330ml", 40000m, new List<int?> { catDoUong, catBia });
                AddItem(section, restaurantId, "Bia Saigon Special", "Bia Saigon Special chai", 30000m, new List<int?> { catDoUong, catBia });
            }
            if (includeWine && catRuouVang.HasValue)
            {
                AddItem(section, restaurantId, "Rượu Vang Đỏ (Ly)", "Ly rượu vang đỏ Chile Cabernet Sauvignon", 150000m, new List<int?> { catDoUong, catRuouVang });
                AddItem(section, restaurantId, "Rượu Vang Trắng (Chai)", "Chai rượu vang trắng Sauvignon Blanc", 750000m, new List<int?> { catDoUong, catRuouVang });
            }
            if (includeCocktail && catCocktail.HasValue)
            {
                AddItem(section, restaurantId, "Mojito Chanh Bạc Hà", "Cocktail Mojito cổ điển", 120000m, new List<int?> { catDoUong, catCocktail });
                AddItem(section, restaurantId, "Passion Fruit Mocktail", "Mocktail chanh dây không cồn", 90000m, new List<int?> { catDoUong, catCocktail });
            }
        }

        private static string RemoveDiacritics(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return text;
            text = text.Normalize(System.Text.NormalizationForm.FormD);
            var chars = text.Where(c => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.NonSpacingMark).ToArray();
            var result = new string(chars).Normalize(System.Text.NormalizationForm.FormC);
            return System.Text.RegularExpressions.Regex.Replace(result, @"\s+", "_"); // Thay khoảng trắng bằng _
        }
    }
}