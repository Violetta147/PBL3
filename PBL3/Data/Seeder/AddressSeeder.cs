using Microsoft.EntityFrameworkCore;
using PBL3.Models; // Đảm bảo namespace này đúng
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace PBL3.Data.Seeder
{
    public static class AddressSeeder
    {
        private static Random _random = new Random();

        public static async Task SeedAsync(ApplicationDbContext context)
        {
            if (await context.Addresses.AnyAsync())
            {
                return; // Đã có dữ liệu
            }

            // --- LẤY USER IDS ĐỂ GÁN ĐỊA CHỈ CÁ NHÂN ---
            var randomUsers = await context.Users
                                        .Where(u => !u.Email.Contains("admin@") && !u.Email.Contains("super.admin@"))
                                        .OrderBy(u => Guid.NewGuid())
                                        .Take(30) // Tăng số lượng user lên để có nhiều địa chỉ hơn
                                        .Select(u => new { u.Id, u.DisplayName })
                                        .ToListAsync();

            var addresses = new List<Address>();

            // --- ĐỊA CHỈ CHO NHÀ HÀNG (UserId sẽ là null) - TẬP TRUNG ĐÀ NẴNG VÀ MỘT SỐ THÀNH PHỐ KHÁC ---
            addresses.AddRange(new List<Address>
            {
                // Đà Nẵng
                new Address { AddressLine1 = "04 Bạch Đằng", Ward = "Phường Bình Hiên", District = "Quận Hải Châu", City = "TP. Đà Nẵng", Latitude = 16.0630, Longitude = 108.2240, UserId = null },
                new Address { AddressLine1 = "Lô 14 Hoàng Sa", Ward = "Phường Mân Thái", District = "Quận Sơn Trà", City = "TP. Đà Nẵng", Latitude = 16.0780, Longitude = 108.2488, UserId = null },
                new Address { AddressLine1 = "4 Lê Duẩn", Ward = "Phường Hải Châu I", District = "Quận Hải Châu", City = "TP. Đà Nẵng", Latitude = 16.0695, Longitude = 108.2218, UserId = null },
                new Address { AddressLine1 = "123 Ông Ích Khiêm", Ward = "Phường Thanh Bình", District = "Quận Hải Châu", City = "TP. Đà Nẵng", Latitude = 16.0660, Longitude = 108.2150, UserId = null },
                new Address { AddressLine1 = "Lô A1-2 Đường Như Nguyệt", Ward = "Phường Thuận Phước", District = "Quận Hải Châu", City = "TP. Đà Nẵng", Latitude = 16.0840, Longitude = 108.2200, UserId = null },
                new Address { AddressLine1 = "270 Nguyễn Văn Linh", Ward = "Phường Thạc Gián", District = "Quận Thanh Khê", City = "TP. Đà Nẵng", Latitude = 16.0595, Longitude = 108.2088, UserId = null },


                // TP. Hồ Chí Minh (Ví dụ 1-2 địa chỉ nhà hàng)
                new Address { AddressLine1 = "22 Nguyễn Huệ", Ward = "Phường Bến Nghé", District = "Quận 1", City = "TP. Hồ Chí Minh", Latitude = 10.7749, Longitude = 106.7034, UserId = null },
                new Address { AddressLine1 = "180 Pasteur", Ward = "Phường Võ Thị Sáu", District = "Quận 3", City = "TP. Hồ Chí Minh", Latitude = 10.7821, Longitude = 106.6926, UserId = null },

                // Hà Nội (Ví dụ 1-2 địa chỉ nhà hàng)
                new Address { AddressLine1 = "29 Phố Tràng Tiền", Ward = "Phường Tràng Tiền", District = "Quận Hoàn Kiếm", City = "TP. Hà Nội", Latitude = 21.0248, Longitude = 105.8526, UserId = null },
                new Address { AddressLine1 = "50 Lý Thường Kiệt", Ward = "Phường Trần Hưng Đạo", District = "Quận Hoàn Kiếm", City = "TP. Hà Nội", Latitude = 21.0215, Longitude = 105.8501, UserId = null },
            });

            // --- ĐỊA CHỈ CÁ NHÂN CỦA NGƯỜI DÙNG (Sổ địa chỉ) ---

            // Danh sách đường phố cho từng thành phố/quận
            var cityData = new Dictionary<string, Dictionary<string, List<string>>>
            {
                ["TP. Đà Nẵng"] = new Dictionary<string, List<string>>
                {
                    ["Quận Hải Châu"] = new List<string> { "Lê Duẩn", "Trần Phú", "Bạch Đằng", "Hùng Vương", "Ông Ích Khiêm", "Nguyễn Văn Linh", "Hoàng Diệu", "Phan Châu Trinh", "2 Tháng 9", "Hàm Nghi", "Đống Đa", "Quang Trung", "Núi Thành", "Tiểu La", "Trưng Nữ Vương", "Như Nguyệt", "Thái Phiên" },
                    ["Quận Thanh Khê"] = new List<string> { "Điện Biên Phủ", "Nguyễn Tri Phương", "Lý Thái Tổ", "Hà Huy Tập", "Dũng Sĩ Thanh Khê", "Trần Cao Vân", "Ông Ích Đường", "Thái Thị Bôi" },
                    ["Quận Sơn Trà"] = new List<string> { "Võ Nguyên Giáp", "Hoàng Sa", "Phạm Văn Đồng", "Ngô Quyền", "Trần Hưng Đạo (Sơn Trà)", "Lê Đức Thọ" }
                },
                ["TP. Hồ Chí Minh"] = new Dictionary<string, List<string>>
                {
                    ["Quận 1"] = new List<string> { "Nguyễn Huệ", "Đồng Khởi", "Lê Lợi", "Pasteur", "Hai Bà Trưng", "Tôn Đức Thắng", "Lý Tự Trọng", "Nam Kỳ Khởi Nghĩa" },
                    ["Quận 3"] = new List<string> { "Võ Văn Tần", "Nguyễn Thị Minh Khai", "Điện Biên Phủ (Quận 3)", "Cách Mạng Tháng Tám (Quận 3)", "Lê Văn Sỹ", "Trần Quốc Thảo" }
                },
                ["TP. Hà Nội"] = new Dictionary<string, List<string>>
                {
                    ["Quận Hoàn Kiếm"] = new List<string> { "Phố Tràng Tiền", "Lý Thường Kiệt", "Hai Bà Trưng (Hoàn Kiếm)", "Hàng Bài", "Đinh Tiên Hoàng", "Lê Thái Tổ", "Hàng Ngang", "Hàng Đào" },
                    ["Quận Ba Đình"] = new List<string> { "Điện Biên Phủ (Ba Đình)", "Hoàng Diệu (Ba Đình)", "Kim Mã", "Nguyễn Chí Thanh", "Đội Cấn", "Liễu Giai" }
                }
            };

            // Danh sách phường tương ứng (đơn giản hóa, bạn có thể làm chi tiết hơn)
            var wardData = new Dictionary<string, Dictionary<string, List<string>>>
            {
                ["TP. Đà Nẵng"] = new Dictionary<string, List<string>>
                {
                    ["Quận Hải Châu"] = new List<string> { "Phường Hải Châu I", "Phường Hải Châu II", "Phường Thạch Thang", "Phường Thanh Bình", "Phường Thuận Phước", "Phường Hòa Thuận Đông", "Phường Bình Hiên", "Phường Nam Dương", "Phường Phước Ninh", "Phường Hòa Cường Bắc" },
                    ["Quận Thanh Khê"] = new List<string> { "Phường Vĩnh Trung", "Phường Tân Chính", "Phường Thạc Gián", "Phường Chính Gián", "Phường Tam Thuận", "Phường Xuân Hà", "Phường An Khê", "Phường Hòa Khê", "Phường Thanh Khê Đông" },
                    ["Quận Sơn Trà"] = new List<string> { "Phường An Hải Bắc", "Phường An Hải Đông", "Phường An Hải Tây", "Phường Mân Thái", "Phường Nại Hiên Đông", "Phường Phước Mỹ", "Phường Thọ Quang" }
                },
                ["TP. Hồ Chí Minh"] = new Dictionary<string, List<string>>
                {
                    ["Quận 1"] = new List<string> { "Phường Bến Nghé", "Phường Bến Thành", "Phường Cầu Kho", "Phường Cầu Ông Lãnh", "Phường Cô Giang", "Phường Đa Kao", "Phường Nguyễn Cư Trinh", "Phường Nguyễn Thái Bình", "Phường Phạm Ngũ Lão", "Phường Tân Định" },
                    ["Quận 3"] = new List<string> { "Phường Võ Thị Sáu", "Phường 1", "Phường 2", "Phường 3", "Phường 4", "Phường 5", "Phường 9", "Phường 10", "Phường 11", "Phường 12", "Phường 13", "Phường 14" }
                },
                ["TP. Hà Nội"] = new Dictionary<string, List<string>>
                {
                    ["Quận Hoàn Kiếm"] = new List<string> { "Phường Tràng Tiền", "Phường Trần Hưng Đạo", "Phường Hàng Bài", "Phường Hàng Bạc", "Phường Hàng Bồ", "Phường Hàng Bông", "Phường Hàng Buồm", "Phường Hàng Mã", "Phường Lý Thái Tổ", "Phường Phan Chu Trinh" },
                    ["Quận Ba Đình"] = new List<string> { "Phường Cống Vị", "Phường Điện Biên", "Phường Đội Cấn", "Phường Giảng Võ", "Phường Kim Mã", "Phường Liễu Giai", "Phường Ngọc Hà", "Phường Ngọc Khánh", "Phường Nguyễn Trung Trực", "Phường Phúc Xá", "Phường Quán Thánh", "Phường Thành Công", "Phường Trúc Bạch", "Phường Vĩnh Phúc" }
                }
            };


            foreach (var user in randomUsers)
            {
                int numberOfAddressesForUser = _random.Next(1, 3);
                for (int i = 0; i < numberOfAddressesForUser; i++)
                {
                    string city, district, ward, streetName;

                    // Phân bổ thành phố ngẫu nhiên, ưu tiên Đà Nẵng
                    int cityRoll = _random.Next(1, 11); // 1-10
                    if (cityRoll <= 6) city = "TP. Đà Nẵng";       // 60% Đà Nẵng
                    else if (cityRoll <= 8) city = "TP. Hồ Chí Minh"; // 20% HCM
                    else city = "TP. Hà Nội";                     // 20% Hà Nội

                    // Chọn quận ngẫu nhiên trong thành phố đã chọn
                    var districtsInCity = cityData[city].Keys.ToList();
                    district = districtsInCity[_random.Next(districtsInCity.Count)];

                    // Chọn phường ngẫu nhiên trong quận đã chọn
                    var wardsInDistrict = wardData[city][district];
                    ward = wardsInDistrict[_random.Next(wardsInDistrict.Count)];

                    // Chọn tên đường ngẫu nhiên trong quận đã chọn
                    var streetsInDistrict = cityData[city][district];
                    streetName = streetsInDistrict[_random.Next(streetsInDistrict.Count)];

                    addresses.Add(new Address
                    {
                        AddressLine1 = $"{_random.Next(1, 500)} {streetName}", // Chỉ số nhà + tên đường
                        Ward = ward,
                        District = district,
                        City = city,
                        Latitude = GenerateRandomLatitude(city),
                        Longitude = GenerateRandomLongitude(city),
                        UserId = user.Id
                    });
                }
            }

            // Thêm một vài địa chỉ cho admin (nếu muốn admin cũng có sổ địa chỉ)
            var adminUser = await context.Users.FirstOrDefaultAsync(u => u.Email == "admin.main@pbl3.com");
            if (adminUser != null)
            {
                addresses.Add(new Address { AddressLine1 = "24 Trần Phú", Ward = "Phường Thạch Thang", District = "Quận Hải Châu", City = "TP. Đà Nẵng", UserId = adminUser.Id });
                addresses.Add(new Address { AddressLine1 = "15 Nguyễn Chí Thanh", Ward = "Phường Hải Châu I", District = "Quận Hải Châu", City = "TP. Đà Nẵng", UserId = adminUser.Id });
            }

            await context.Addresses.AddRangeAsync(addresses);
            await context.SaveChangesAsync();
        }

        // Hàm trợ giúp tạo tọa độ ngẫu nhiên gần một thành phố
        private static double? GenerateRandomLatitude(string city)
        {
            double baseLat = 0;
            if (city == "TP. Đà Nẵng") baseLat = 16.0470;
            else if (city == "TP. Hồ Chí Minh") baseLat = 10.7769;
            else if (city == "TP. Hà Nội") baseLat = 21.0285;
            else return null;
            return baseLat + (_random.NextDouble() * 0.1 - 0.05); // Dao động trong khoảng +/- 0.05 độ
        }

        private static double? GenerateRandomLongitude(string city)
        {
            double baseLng = 0;
            if (city == "TP. Đà Nẵng") baseLng = 108.2200;
            else if (city == "TP. Hồ Chí Minh") baseLng = 106.7009;
            else if (city == "TP. Hà Nội") baseLng = 105.8542;
            else return null;
            return baseLng + (_random.NextDouble() * 0.1 - 0.05); // Dao động trong khoảng +/- 0.05 độ
        }
    }
}