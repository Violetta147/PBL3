// Data/Seeders/TagSeeder.cs
using Microsoft.EntityFrameworkCore;
using PBL3.Models; // Đảm bảo namespace này đúng
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace PBL3.Data.Seeder
{
    public static class TagSeeder
    {
        public static async Task SeedTagsAsync(ApplicationDbContext context)
        {
            // Chỉ seed nếu bảng Tags chưa có dữ liệu
            if (await context.Tags.AnyAsync())
            {
                Console.WriteLine("Tags đã tồn tại trong database. Bỏ qua việc seed Tag cơ bản.");
                return;
            }

            var now = DateTime.UtcNow;
            var tags = new List<Tag>
            {
                new Tag { Name = "Không nhận trẻ em", Description = "Không nhận phục vụ trẻ em.", IconUrl = "/images/tag_icons/no_children.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Có Chỗ Đậu Xe Ô Tô", Description = "Có khu vực đậu xe cho ô tô.", IconUrl = "/images/tag_icons/parking_car.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Có Chỗ Đậu Xe Máy", Description = "Có khu vực đậu xe cho xe máy.", IconUrl = "/images/tag_icons/parking_moto.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "View Đẹp", Description = "Nhà hàng có không gian với tầm nhìn đẹp (sông, biển, thành phố...).", IconUrl = "/images/tag_icons/beautiful_view.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Thanh Toán Thẻ", Description = "Chấp nhận thanh toán bằng thẻ tín dụng/ghi nợ.", IconUrl = "/images/tag_icons/credit_card.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Thanh Toán Ví Điện Tử", Description = "Chấp nhận thanh toán bằng MoMo, ZaloPay, VNPay...", IconUrl = "/images/tag_icons/ewallet.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Phục Vụ Ngoài Trời", Description = "Có không gian phục vụ ngoài trời, ban công, sân vườn.", IconUrl = "/images/tag_icons/outdoor_seating.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Phòng Riêng/VIP", Description = "Có phòng riêng cho nhóm hoặc sự kiện.", IconUrl = "/images/tag_icons/vip_room.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Thân Thiện Với Trẻ Em", Description = "Không gian phù hợp, có ghế trẻ em, hoặc khu vui chơi nhỏ.", IconUrl = "/images/tag_icons/kids_friendly.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Cho Phép Mang Thú Cưng", Description = "Chào đón khách hàng mang theo thú cưng (có điều kiện).", IconUrl = "/images/tag_icons/pet_friendly.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Giá Bình Dân", Description = "Mức giá phải chăng, phù hợp với nhiều đối tượng.", IconUrl = "/images/tag_icons/affordable.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Cao Cấp/Sang Trọng", Description = "Không gian và dịch vụ cao cấp, mức giá tương xứng.", IconUrl = "/images/tag_icons/luxury.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Lãng Mạn", Description = "Không gian phù hợp cho các cặp đôi.", IconUrl = "/images/tag_icons/romantic.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Phù Hợp Nhóm Đông", Description = "Có không gian và sắp xếp phù hợp cho nhóm đông người.", IconUrl = "/images/tag_icons/group_friendly.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Giao Hàng Tận Nơi", Description = "Có dịch vụ giao hàng tận nơi.", IconUrl = "/images/tag_icons/delivery.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Mang Về (Take Away)", Description = "Có dịch vụ cho khách mua mang về.", IconUrl = "/images/tag_icons/take_away.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Không Hút Thuốc", Description = "Toàn bộ nhà hàng là khu vực không hút thuốc.", IconUrl = "/images/tag_icons/no_smoking.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Có Điều Hòa", Description = "Không gian được trang bị máy điều hòa không khí.", IconUrl = "/images/tag_icons/air_conditioner.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Nhạc Sống/DJ", Description = "Có chương trình nhạc sống hoặc DJ vào một số thời điểm.", IconUrl = "/images/tag_icons/live_music.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Buffet", Description = "Phục vụ theo hình thức buffet.", IconUrl = "/images/tag_icons/buffet.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Món Chay", Description = "Có phục vụ các món ăn chay trong thực đơn.", IconUrl = "/images/tag_icons/vegetarian_food.png", CreatedAt = now, UpdatedAt = now },
                new Tag { Name = "Giữ Xe Miễn Phí", Description = "Khách hàng được giữ xe miễn phí.", IconUrl = "/images/tag_icons/free_parking.png", CreatedAt = now, UpdatedAt = now }
            };

            await context.Tags.AddRangeAsync(tags);
            await context.SaveChangesAsync();
            Console.WriteLine("Đã seed các Tags cơ bản (bao gồm IconUrl).");
        }
    }
}