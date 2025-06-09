using Microsoft.EntityFrameworkCore; // Cần cho Include, AnyAsync, etc.
using PBL3.Models; // Namespace chứa các model của bạn
using System;
using System.Linq; // Cần cho Any()
using System.Threading.Tasks; // Cần cho async/await

namespace PBL3.Data.Seeder
{
    public class CuisineTypeSeeder
    {
        public static async Task SeedCuisineTypesAsync(ApplicationDbContext context)
        {
            // Chỉ seed nếu bảng CuisineTypes chưa có dữ liệu
            if (!await context.CuisineTypes.AnyAsync())
            {
                var now = DateTime.UtcNow;
                var cuisineTypes = new List<CuisineType>
        {
            // --- Ẩm thực Việt Nam theo món đặc trưng ---
            new CuisineType
            {
                Name = "Cà phê",
                IconUrl = "/images/cuisine_icons/coffee.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Mỳ các loại",
                IconUrl = "/images/cuisine_icons/noodles.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Phở & Bún các loại",
                IconUrl = "/images/cuisine_icons/pho_noodles.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Cơm Việt Nam",
                IconUrl = "/images/cuisine_icons/vietnamese_rice.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Bánh mì & Xôi",
                IconUrl = "/images/cuisine_icons/banhmi_xoi.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Món cuốn & Gỏi",
                IconUrl = "/images/cuisine_icons/spring_rolls.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Lẩu & Nướng",
                IconUrl = "/images/cuisine_icons/hotpot_bbq.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Đồ ăn vặt / Đường phố",
                IconUrl = "/images/cuisine_icons/streetfood_vn.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Hải sản Việt",
                IconUrl = "/images/cuisine_icons/vietnamese_seafood.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Món Chay Việt",
                IconUrl = "/images/cuisine_icons/vietnamese_vegetarian.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Các loại bánh Việt",
                IconUrl = "/images/cuisine_icons/vietnamese_traditional.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },

            // --- Ẩm thực Quốc tế phổ biến tại Việt Nam ---
            new CuisineType
            {
                Name = "Ẩm thực Nhật Bản",
                IconUrl = "/images/cuisine_icons/japanese.png",
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Ẩm thực Hàn Quốc",
                IconUrl = "/images/cuisine_icons/korean.png",
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Ẩm thực Trung Quốc",
                IconUrl = "/images/cuisine_icons/chinese.png",
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Dim Sum & Món hấp", // Tách riêng để dễ tìm kiếm
                IconUrl = "/images/cuisine_icons/dimsum.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Ẩm thực Thái Lan",
                IconUrl = "/images/cuisine_icons/thai.png",
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Ẩm thực Ý (Pizza & Pasta)",
                IconUrl = "/images/cuisine_icons/italian.png",
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Đồ ăn nhanh (Burger, Gà rán)",
                IconUrl = "/images/cuisine_icons/fastfood.png",
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Steak & Đồ Âu",
                IconUrl = "/images/cuisine_icons/steak_western.png",
                CreatedAt = now,
                UpdatedAt = now
            },
             new CuisineType
            {
                Name = "Ẩm thực Ấn Độ",
                IconUrl = "/images/cuisine_icons/indian.png",
                CreatedAt = now,
                UpdatedAt = now
            },

            // --- Loại hình & Thời điểm ăn uống ---
            new CuisineType
            {
                Name = "Trà sữa & Giải khát",
                IconUrl = "/images/cuisine_icons/bubble_tea.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Bánh ngọt & Kem",
                IconUrl = "/images/cuisine_icons/desserts_cakes.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Ăn sáng",
                IconUrl = "/images/cuisine_icons/breakfast.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            },
            new CuisineType
            {
                Name = "Khác",
                IconUrl = "/images/cuisine_icons/another.png", // Cần tạo icon này
                CreatedAt = now,
                UpdatedAt = now
            }
        };

                await context.CuisineTypes.AddRangeAsync(cuisineTypes);
                await context.SaveChangesAsync();
            }
        }
    }
}
