// Data/Seeders/RestaurantSeeder.cs
using Microsoft.EntityFrameworkCore;
using PBL3.Models; // Đảm bảo namespace này đúng
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.Data.Seeder
{
    public static class RestaurantSeeder
    {
        private static Random _random = new Random();

        public static async Task SeedAsync(ApplicationDbContext context)
        {
            if (await context.Restaurants.AnyAsync())
            {
                return; // Đã có dữ liệu
            }

            var restaurantAddresses = await context.Addresses
                                                .Where(a => a.UserId == null)
                                                .ToListAsync();

            var potentialOwners = await context.Users
                                .OrderBy(u => Guid.NewGuid()) // Sắp xếp ngẫu nhiên để chọn
                                .Take(20)
                                .Select(u => u.Id) // u.Id ở đây là string
                                .ToListAsync();

            if (!restaurantAddresses.Any() || !potentialOwners.Any())
            {
                Console.WriteLine("Không tìm thấy đủ địa chỉ nhà hàng hoặc chủ sở hữu tiềm năng để seed nhà hàng.");
                return;
            }

            var restaurantsToSeed = new List<Restaurant>();

            // SỬA Ở ĐÂY: Sử dụng cú pháp ValueTuple để khai báo kiểu của danh sách
            var restaurantTemplates = new List<(
                string Name, string Description, string TargetCity, string TargetAddressLine1Part,
                int MinPrice, int MaxPrice, string ImageUrlSuffix, RestaurantStatus Status,
                List<OperatingHour> OperatingHours
            )>
            {
                // --- Đà Nẵng ---
                // SỬA Ở ĐÂY: Sử dụng cú pháp ValueTuple để tạo đối tượng
                (
                    Name: "Madame Lân - Đặc Sản Đà Thành",
                    Description: "Khám phá ẩm thực truyền thống Đà Nẵng trong không gian hoài cổ ven sông Hàn. Mì Quảng, Bánh Xèo, Nem Lụi...",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "04 Bạch Đằng",
                    MinPrice: 80000, MaxPrice: 300000, ImageUrlSuffix: "madame_lan.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 9, closeHour: 22)
                ),
                (
                    Name: "Hải Sản Bé Mặn Biển Đông",
                    Description: "Hải sản tươi sống, đa dạng cách chế biến. Không gian rộng rãi, thoáng đãng, view biển tuyệt đẹp.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "Lô 14 Hoàng Sa",
                    MinPrice: 150000, MaxPrice: 1000000, ImageUrlSuffix: "haisan_be_man.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 10, closeHour: 23)
                ),
                // ... (Thêm các nhà hàng khác với cú pháp ValueTuple tương tự) ...
                (
                    Name: "Bếp Trần - Món Ngon Xứ Quảng",
                    Description: "Chuỗi nhà hàng nổi tiếng với các món đặc sản Quảng Nam - Đà Nẵng như bánh tráng cuốn thịt heo, bún mắm...",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "4 Lê Duẩn",
                    MinPrice: 70000, MaxPrice: 250000, ImageUrlSuffix: "bep_tran.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 8, closeHour: 22)
                ),
                (
                    Name: "Cơm Niêu Nhà Đỏ Đà Nẵng",
                    Description: "Cơm niêu truyền thống, các món ăn dân dã Việt Nam. Không gian ấm cúng, phù hợp gia đình.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "123 Ông Ích Khiêm",
                    MinPrice: 60000, MaxPrice: 200000, ImageUrlSuffix: "comnieu_nhado.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 10, closeHour: 21, breakStartHour:14, breakEndHour:17)
                ),
                (
                    Name: "Wonderlust Bakery & Coffee DN",
                    Description: "Không gian cà phê và bánh ngọt lãng mạn, view sông Hàn và cầu Thuận Phước. Đồ uống đa dạng.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "Lô A1-2 Đường Như Nguyệt",
                    MinPrice: 40000, MaxPrice: 150000, ImageUrlSuffix: "wonderlust_coffee.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 7, closeHour: 22)
                ),
                (
                    Name: "Mỳ Quảng Bà Mua Chính Gốc",
                    Description: "Thưởng thức tô Mỳ Quảng đậm đà hương vị truyền thống, nhiều loại topping. Giá bình dân.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "270 Nguyễn Văn Linh",
                    MinPrice: 35000, MaxPrice: 70000, ImageUrlSuffix: "myquang_bamua.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 6, closeHour: 21)
                ),
                (
                    Name: "The Rachel Restaurant & Bar",
                    Description: "Nhà hàng Âu sang trọng, ẩm thực tinh tế kết hợp quầy bar hiện đại. View biển Mỹ Khê.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "Võ Nguyên Giáp", // Cần địa chỉ cụ thể hơn nếu có trong AddressSeeder
                    MinPrice: 300000, MaxPrice: 1500000, ImageUrlSuffix: "the_rachel.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: false, days: new List<DayOfWeek>{DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday}, openHour: 17, closeHour: 23, fridaySaturdayCloseHour: 0)
                ),
                (
                    Name: "Quán Chay An Lạc Tâm",
                    Description: "Thực đơn chay phong phú, các món ăn thanh đạm, tốt cho sức khỏe. Không gian yên tĩnh.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "123 Ông Ích Khiêm", // Cần đảm bảo địa chỉ này có trong AddressSeeder
                    MinPrice: 30000, MaxPrice: 100000, ImageUrlSuffix: "quanchay_anlac.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay:true, openHour:8, closeHour:20)
                ),
                (
                    Name: "BBQ Lưới - Nướng & Lẩu Hàn Quốc",
                    Description: "Buffet nướng lẩu Hàn Quốc với thịt bò Mỹ, hải sản tươi ngon. Giá cả hợp lý.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "Phan Đăng Lưu", // Cần địa chỉ cụ thể hơn
                    MinPrice: 199000, MaxPrice: 399000, ImageUrlSuffix: "bbq_luoi.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay:true, openHour:11, closeHour:22)
                ),
                (
                    Name: "Cà Phê Cộng Đà Nẵng",
                    Description: "Không gian cà phê độc đáo, mang đậm phong cách bao cấp. Đồ uống truyền thống và hiện đại.",
                    TargetCity: "TP. Đà Nẵng",
                    TargetAddressLine1Part: "Bạch Đằng", // Cần địa chỉ cụ thể hơn
                    MinPrice: 35000, MaxPrice: 80000, ImageUrlSuffix: "caphe_cong.jpg", Status: RestaurantStatus.TemporarilyClosed,
                    OperatingHours: GenerateOperatingHours(allDay:true, openHour:7, closeHour:23)
                ),

                // --- TP. Hồ Chí Minh ---
                (
                    Name: "Phở Hòa Pasteur Sài Gòn",
                    Description: "Một trong những quán phở lâu đời và nổi tiếng nhất Sài Gòn. Nước dùng trong, thịt mềm.",
                    TargetCity: "TP. Hồ Chí Minh",
                    TargetAddressLine1Part: "22 Nguyễn Huệ", // Hoặc "Pasteur" nếu địa chỉ trong AddressSeeder là vậy
                    MinPrice: 70000, MaxPrice: 150000, ImageUrlSuffix: "pho_hoa_pasteur.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 6, closeHour: 23)
                ),
                (
                    Name: "Cục Gạch Quán - Món Ăn Gia Đình",
                    Description: "Không gian kiến trúc độc đáo, phục vụ các món ăn Việt Nam truyền thống như ở nhà. Nhiều người nổi tiếng ghé thăm.",
                    TargetCity: "TP. Hồ Chí Minh",
                    TargetAddressLine1Part: "180 Pasteur",
                    MinPrice: 150000, MaxPrice: 500000, ImageUrlSuffix: "cuc_gach_quan.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 10, closeHour: 22)
                ),
                 (
                    Name: "Pizza 4P's Lê Thánh Tôn",
                    Description: "Chuỗi pizza nổi tiếng với phô mai nhà làm và các vị pizza sáng tạo. Không gian hiện đại.",
                    TargetCity: "TP. Hồ Chí Minh",
                    TargetAddressLine1Part: "22 Nguyễn Huệ", // Giả sử dùng chung địa chỉ với Phở Hòa cho demo
                    MinPrice: 180000, MaxPrice: 500000, ImageUrlSuffix: "pizza_4ps.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay:true, openHour:10, closeHour:23)
                ),
                (
                    Name: "The Refinery Saigon",
                    Description: "Nhà hàng Pháp cổ điển nằm trong một nhà máy thuốc phiện cũ. Không gian lãng mạn, ẩm thực Pháp tinh tế.",
                    TargetCity: "TP. Hồ Chí Minh",
                    TargetAddressLine1Part: "180 Pasteur", // Giả sử dùng chung địa chỉ với Cục Gạch cho demo
                    MinPrice: 250000, MaxPrice: 800000, ImageUrlSuffix: "the_refinery.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay:true, openHour:11, closeHour:23)
                ),


                // --- Hà Nội ---
                (
                    Name: "Chả Cá Lã Vọng Hà Thành",
                    Description: "Món chả cá gia truyền nức tiếng Hà Nội. Cá lăng tươi ngon, ăn kèm bún, rau thơm, mắm tôm.",
                    TargetCity: "TP. Hà Nội",
                    TargetAddressLine1Part: "29 Phố Tràng Tiền",
                    MinPrice: 150000, MaxPrice: 300000, ImageUrlSuffix: "chaca_lavong.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 10, closeHour: 22)
                ),
                (
                    Name: "Bún Chả Hương Liên (Obama Bun Cha)",
                    Description: "Quán bún chả nổi tiếng sau chuyến thăm của cựu Tổng thống Obama. Hương vị truyền thống, giá bình dân.",
                    TargetCity: "TP. Hà Nội",
                    TargetAddressLine1Part: "50 Lý Thường Kiệt",
                    MinPrice: 50000, MaxPrice: 100000, ImageUrlSuffix: "buncha_huonglien.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay: true, openHour: 8, closeHour: 20)
                ),
                 (
                    Name: "Giảng Cafe - Cà Phê Trứng",
                    Description: "Quán cà phê trứng lâu đời và độc đáo nhất Hà Nội. Vị béo ngậy, thơm lừng.",
                    TargetCity: "TP. Hà Nội",
                    TargetAddressLine1Part: "Nguyễn Hữu Huân", // Cần địa chỉ cụ thể
                    MinPrice: 25000, MaxPrice: 60000, ImageUrlSuffix: "giang_cafe.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay:true, openHour:7, closeHour:22)
                ),
                (
                    Name: "Nhà Hàng Lục Thủy - View Hồ Gươm",
                    Description: "Nhà hàng sang trọng với view nhìn ra Hồ Hoàn Kiếm. Ẩm thực Việt và quốc tế.",
                    TargetCity: "TP. Hà Nội",
                    TargetAddressLine1Part: "29 Phố Tràng Tiền", // Giả sử dùng chung địa chỉ với Chả Cá cho demo
                    MinPrice: 400000, MaxPrice: 2000000, ImageUrlSuffix: "luc_thuy_restaurant.jpg", Status: RestaurantStatus.Open,
                    OperatingHours: GenerateOperatingHours(allDay:true, openHour:10, closeHour:23)
                )
            };

            int ownerIndex = 0;

            foreach (var template in restaurantTemplates)
            {
                var targetAddress = restaurantAddresses.FirstOrDefault(a =>
                    a.City == template.TargetCity &&
                    a.AddressLine1.Contains(template.TargetAddressLine1Part, StringComparison.OrdinalIgnoreCase)); // Thêm IgnoreCase để linh hoạt hơn

                if (targetAddress == null)
                {
                    Console.WriteLine($"Không tìm thấy địa chỉ cho nhà hàng: {template.Name} (Tìm kiếm: '{template.TargetAddressLine1Part}' ở {template.TargetCity}). Bỏ qua.");
                    continue;
                }

                string ownerId = potentialOwners[ownerIndex % potentialOwners.Count];
                ownerIndex++;

                var restaurant = new Restaurant
                {
                    Name = template.Name,
                    Description = template.Description,
                    AddressId = targetAddress.Id,
                    PhoneNumber = $"0{_random.Next(2, 10)}{_random.Next(10000000, 99999999)}",
                    Website = $"http://{RemoveDiacritics(template.Name).ToLower().Replace(" ", "-").Replace("&", "and").Replace("'", "")}.example.com",
                    MinTypicalPrice = template.MinPrice,
                    MaxTypicalPrice = template.MaxPrice,
                    MainImageUrl = $"/images/restaurants/{template.ImageUrlSuffix}",
                    Status = template.Status,
                    OwnerId = ownerId,
                    AverageRating = Math.Round(3.5 + _random.NextDouble() * 1.5, 1),
                    ReviewCount = _random.Next(20, 500),
                    CreatedAt = DateTime.UtcNow.AddDays(-_random.Next(30, 700)),
                    UpdatedAt = DateTime.UtcNow.AddDays(-_random.Next(1, 29)),
                    OperatingHours = template.OperatingHours
                };
                restaurantsToSeed.Add(restaurant);
            }

            if (restaurantsToSeed.Any())
            {
                await context.Restaurants.AddRangeAsync(restaurantsToSeed);
                await context.SaveChangesAsync();
            }
        }

        private static List<OperatingHour> GenerateOperatingHours(
            bool allDay, // Tham số này không còn dùng trực tiếp, logic dựa trên days
            int openHour, int closeHour,
            int? breakStartHour = null, int? breakEndHour = null,
            List<DayOfWeek> days = null,
            int? fridaySaturdayCloseHour = null)
        {
            var hours = new List<OperatingHour>();
            var daysOfWeekToApply = days ?? Enum.GetValues(typeof(DayOfWeek)).Cast<DayOfWeek>().ToList();

            foreach (var day in daysOfWeekToApply)
            {
                int currentCloseHour = closeHour;
                if (fridaySaturdayCloseHour.HasValue && (day == DayOfWeek.Friday || day == DayOfWeek.Saturday))
                {
                    // Nếu giờ đóng cửa đặc biệt là 0 (qua đêm), set thành 23:59:59
                    currentCloseHour = (fridaySaturdayCloseHour.Value == 0) ? 23 : fridaySaturdayCloseHour.Value;
                    // Nếu là 0, nghĩa là 24:00, ta có thể hiểu là đóng cửa vào 23:59:59 của ngày đó
                    // Hoặc bạn cần logic phức tạp hơn để xử lý qua đêm thực sự (2 bản ghi cho 2 ngày)
                }

                TimeSpan actualCloseTime;
                if (currentCloseHour == 0 || currentCloseHour == 24) // Xử lý trường hợp đóng cửa lúc nửa đêm
                {
                    actualCloseTime = new TimeSpan(23, 59, 59);
                }
                else
                {
                    actualCloseTime = new TimeSpan(currentCloseHour, 0, 0);
                }


                if (breakStartHour.HasValue && breakEndHour.HasValue && breakStartHour < breakEndHour && openHour < breakStartHour && breakEndHour < currentCloseHour)
                {
                    hours.Add(new OperatingHour { DayOfWeek = day, OpenTime = new TimeSpan(openHour, 0, 0), CloseTime = new TimeSpan(breakStartHour.Value, 0, 0) });
                    hours.Add(new OperatingHour { DayOfWeek = day, OpenTime = new TimeSpan(breakEndHour.Value, 0, 0), CloseTime = actualCloseTime });
                }
                else
                {
                    hours.Add(new OperatingHour { DayOfWeek = day, OpenTime = new TimeSpan(openHour, 0, 0), CloseTime = actualCloseTime });
                }
            }
            return hours;
        }

        private static string RemoveDiacritics(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return text;
            text = text.Normalize(System.Text.NormalizationForm.FormD);
            var chars = text.Where(c => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.NonSpacingMark).ToArray();
            return new string(chars).Normalize(System.Text.NormalizationForm.FormC);
        }
    }
}