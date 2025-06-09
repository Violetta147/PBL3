using Azure;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PBL3.Models; // Đảm bảo namespace này chứa tất cả các model của bạn

namespace PBL3.Data
{
    public class ApplicationDbContext : IdentityDbContext<AppUser>
    {
        // Khai báo DbSet cho tất cả các model của bạn
        public DbSet<Restaurant> Restaurants { get; set; }
        public DbSet<Review> Reviews { get; set; }
        public DbSet<RestaurantPhoto> RestaurantPhotos { get; set; }
        public DbSet<ReviewPhoto> ReviewPhotos { get; set; }
        public DbSet<MenuItemPhoto> MenuItemPhotos { get; set; }
        public DbSet<Menu> Menus { get; set; }
        public DbSet<MenuSection> MenuSections { get; set; }
        public DbSet<MenuItem> MenuItems { get; set; }
        public DbSet<Category> Categories { get; set; } // Category để tag món ăn
        public DbSet<MenuItemCategory> MenuItemCategories { get; set; }

        // Các model cho CuisineType và Tag (nếu bạn đã tạo chúng)
        public DbSet<CuisineType> CuisineTypes { get; set; }
        public DbSet<RestaurantCuisine> RestaurantCuisines { get; set; } // Bảng nối
        public DbSet<Tag> Tags { get; set; } // Tag cho nhà hàng (khác với Category cho món ăn)
        public DbSet<RestaurantTag> RestaurantTags { get; set; } // Bảng nối
        public DbSet<Address> Addresses { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<OrderLine> OrderLines { get; set; }
        public DbSet<OrderLog> OrderLogs { get; set; }
        public DbSet<Promotion> Promotions { get; set; }
        public DbSet<PromotionApplicableItem> PromotionApplicableItems { get; set; }
        public DbSet<PromotionApplicableCategory> PromotionApplicableCategories { get; set; }
        public DbSet<UserPromotionUsage> UserPromotionUsages { get; set; }
        public DbSet<OperatingHour> OperatingHours { get; set; }        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder); // Rất quan trọng, gọi để cấu hình Identity trước

            // --- Relationships for Restaurant ---
            builder.Entity<Restaurant>(entity => {
                entity.HasMany(r => r.Reviews)
                    .WithOne(rev => rev.Restaurant)
                    .HasForeignKey(rev => rev.RestaurantId)
                    .OnDelete(DeleteBehavior.Restrict); // Giữ Restrict ở đây

                entity.HasMany(r => r.Photos) // Bây giờ là RestaurantPhotos
                    .WithOne(p => p.Restaurant)
                    .HasForeignKey(p => p.RestaurantId)
                    .OnDelete(DeleteBehavior.Cascade); // Ảnh của nhà hàng nên xóa theo nhà hàng

                entity.HasMany(r => r.Menus)
                    .WithOne(m => m.Restaurant)
                    .HasForeignKey(m => m.RestaurantId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(r => r.MenuItems)
                    .WithOne(mi => mi.Restaurant)
                    .HasForeignKey(mi => mi.RestaurantId)
                    .OnDelete(DeleteBehavior.Restrict);

                // --- THÊM CẤU HÌNH CHO Restaurant - Promotion ---
                entity.HasMany(r => r.Promotions)
                    .WithOne(p => p.Restaurant) // Promotion có một Restaurant (nullable)
                    .HasForeignKey(p => p.RestaurantId) // Khóa ngoại trong Promotion
                    .IsRequired(false) // Vì Promotion.RestaurantId là nullable
                    .OnDelete(DeleteBehavior.SetNull); // Nếu Restaurant bị xóa, Promotion đó không còn thuộc Restaurant nào
                                                       // Hoặc Restrict nếu bạn không muốn xóa Restaurant nếu nó còn Promotion
                                                       // SetNull có vẻ hợp lý hơn để Promotion có thể là của hệ thống.
            });

            // --- Relationships for Review ---
            builder.Entity<Review>(entity => {
                //entity.HasOne(rev => rev.Restaurant)
                //    .WithMany(r => r.Reviews)
                //    .HasForeignKey(rev => rev.RestaurantId)
                //    .OnDelete(DeleteBehavior.Restrict); // Đã cấu hình ở Restaurant

                entity.HasOne(r => r.User)
                    .WithMany()
                    .HasForeignKey(r => r.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(rev => rev.Photos) // Bây giờ là ReviewPhotos
                    .WithOne(p => p.Review)
                    .HasForeignKey(p => p.ReviewId)
                    .OnDelete(DeleteBehavior.Cascade); // Ảnh của review nên xóa theo review
            });

            // --- Relationships for Menu ---
            builder.Entity<Menu>()
                .HasMany(m => m.MenuSections)
                .WithOne(ms => ms.Menu)
                .HasForeignKey(ms => ms.MenuId)
                .OnDelete(DeleteBehavior.Cascade); // Khi Menu bị xóa, các Section của nó bị xóa

            // --- Relationships for MenuSection ---
            builder.Entity<MenuSection>()
                .HasMany(ms => ms.MenuItems)
                .WithOne(mi => mi.MenuSection)
                .HasForeignKey(mi => mi.MenuSectionId)
                .IsRequired(false) // Vì MenuSectionId trong MenuItem là nullable
                .OnDelete(DeleteBehavior.SetNull); // <<< THAY ĐỔI QUAN TRỌNG: Khi MenuSection bị xóa, MenuItem không bị xóa, MenuSectionId được set null

            // --- Relationships for MenuItem ---
            builder.Entity<MenuItem>(entity => {
                // entity.HasOne(mi => mi.Restaurant) ... đã cấu hình ở Restaurant

                entity.HasOne(mi => mi.MenuSection)
                    .WithMany(ms => ms.MenuItems)
                    .HasForeignKey(mi => mi.MenuSectionId)
                    .IsRequired(false)
                    .OnDelete(DeleteBehavior.SetNull);

                entity.HasMany(mi => mi.Photos) // Bây giờ là MenuItemPhotos
                    .WithOne(p => p.MenuItem)
                    .HasForeignKey(p => p.MenuItemId)
                    .OnDelete(DeleteBehavior.Cascade); // Ảnh của món ăn nên xóa theo món ăn

                entity.Property(p => p.Price)
                    .HasColumnType("decimal(18,2)");
            });

            // Address
            builder.Entity<Address>(entity =>
            {
                // Mối quan hệ Address - AppUser (Sổ địa chỉ người dùng)
                entity.HasOne(a => a.User)
                    .WithMany(u => u.Addresses) // Giả sử AppUser có ICollection<Address> Addresses
                    .HasForeignKey(a => a.UserId)
                    .IsRequired(false) // UserId trong Address là nullable
                    .OnDelete(DeleteBehavior.ClientSetNull); // Nếu User bị xóa, UserId trong Address của họ thành null
                                                             // Hoặc Cascade nếu muốn xóa địa chỉ khi User bị xóa
            });

            // Order
            builder.Entity<Order>(entity =>
            {
                entity.HasOne(o => o.User) // Người đặt hàng
                    .WithMany() // Giả sử AppUser không có ICollection<Order> OrdersPlaced
                    .HasForeignKey(o => o.UserId)
                    .OnDelete(DeleteBehavior.Restrict); // Không cho xóa User nếu họ có đơn hàng.
                                                        // Hoặc Cascade nếu chính sách của bạn là xóa đơn hàng khi User bị xóa.
                                                        // Restrict thường an toàn hơn cho dữ liệu giao dịch.

                entity.HasOne(o => o.Restaurant) // Nhà hàng của đơn hàng
                    .WithMany() // Restaurant không có ICollection<Order> trực tiếp
                    .HasForeignKey(o => o.RestaurantId)
                    .OnDelete(DeleteBehavior.Restrict); // Không cho xóa Restaurant nếu nó có đơn hàng.

                entity.HasOne(o => o.ShippingAddress) // Địa chỉ giao hàng
                    .WithMany(a => a.OrdersAsShippingAddress) // Address có ICollection<Order>
                    .HasForeignKey(o => o.ShippingAddressId)
                    .OnDelete(DeleteBehavior.Restrict); // Không cho xóa Address nếu nó đang được dùng làm địa chỉ giao hàng.

                // --- THÊM CẤU HÌNH CHO Order - Promotion ---
                entity.HasOne(o => o.AppliedPromotion)
                    .WithMany() // Promotion không có ICollection<Order> OrdersAppliedThisPromotion (tạm thời)
                    .HasForeignKey(o => o.AppliedPromotionId)
                    .IsRequired(false) // AppliedPromotionId là nullable
                    .OnDelete(DeleteBehavior.SetNull); // Nếu Promotion bị xóa, đơn hàng vẫn còn, chỉ mất liên kết.
                // ---------------------------------------------
            });

            // OrderLine
            builder.Entity<OrderLine>(entity =>
            {
                entity.HasOne(ol => ol.Order)
                    .WithMany(o => o.OrderLines)
                    .HasForeignKey(ol => ol.OrderId)
                    .OnDelete(DeleteBehavior.Cascade); // Khi Order bị xóa, các OrderLine của nó bị xóa.

                entity.HasOne(ol => ol.MenuItem)
                    .WithMany() // MenuItem không có ICollection<OrderLine>
                    .HasForeignKey(ol => ol.MenuItemId)
                    .OnDelete(DeleteBehavior.Restrict); // Không cho xóa MenuItem nếu nó có trong OrderLine.
                
                entity.HasOne(ol => ol.AppliedItemPromotion)
                    .WithMany()
                    .HasForeignKey(ol => ol.AppliedItemPromotionId)
                    .IsRequired(false)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // OrderLog
            builder.Entity<OrderLog>(entity =>
            {
                entity.HasOne(ol => ol.Order)
                    .WithMany(o => o.OrderLogs)
                    .HasForeignKey(ol => ol.OrderId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(ol => ol.ChangedByUser)
                    .WithMany() // AppUser không có ICollection<OrderLog>
                    .HasForeignKey(ol => ol.ChangedByUserId)
                    .IsRequired(false)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // Promotion
            builder.Entity<Promotion>(entity =>
            {
                // Đảm bảo CouponCode là duy nhất nếu không null
                entity.HasIndex(p => p.CouponCode)
                    .IsUnique()
                    .HasFilter("[CouponCode] IS NOT NULL"); // Chỉ áp dụng unique cho các giá trị không null

                // Mối quan hệ Promotion - Restaurant đã được cấu hình từ phía Restaurant
            });

            // PromotionApplicableItem (Many-to-Many giữa Promotion và MenuItem)
            builder.Entity<PromotionApplicableItem>(entity =>
            {
                entity.HasKey(pai => new { pai.PromotionId, pai.MenuItemId }); // Khóa chính phức hợp

                entity.HasOne(pai => pai.Promotion)
                    .WithMany(p => p.ApplicableItems) // Promotion có ICollection<PromotionApplicableItem>
                    .HasForeignKey(pai => pai.PromotionId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(pai => pai.MenuItem)
                    .WithMany(mi => mi.PromotionsAppliedToThisItem) // MenuItem có ICollection<PromotionApplicableItem>
                    .HasForeignKey(pai => pai.MenuItemId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // PromotionApplicableCategory (Many-to-Many giữa Promotion và Category)
            builder.Entity<PromotionApplicableCategory>(entity =>
            {
                entity.HasKey(pac => new { pac.PromotionId, pac.CategoryId });

                entity.HasOne(pac => pac.Promotion)
                    .WithMany(p => p.ApplicableCategories) // Promotion có ICollection<PromotionApplicableCategory>
                    .HasForeignKey(pac => pac.PromotionId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(pac => pac.Category)
                    .WithMany(c => c.PromotionsAppliedToThisCategory) // Category có ICollection<PromotionApplicableCategory>
                    .HasForeignKey(pac => pac.CategoryId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // UserPromotionUsage (Many-to-Many giữa AppUser và Promotion với thuộc tính bổ sung)
            builder.Entity<UserPromotionUsage>(entity =>
            {
                entity.HasKey(upu => new { upu.UserId, upu.PromotionId }); // Khóa chính phức hợp

                entity.HasOne(upu => upu.User)
                    .WithMany(u => u.PromotionUsages) // AppUser có ICollection<UserPromotionUsage>
                    .HasForeignKey(upu => upu.UserId)
                    .OnDelete(DeleteBehavior.Cascade); // Nếu User bị xóa, lịch sử sử dụng của họ cũng bị xóa

                entity.HasOne(upu => upu.Promotion)
                    .WithMany(p => p.UserUsages) // Promotion có ICollection<UserPromotionUsage>
                    .HasForeignKey(upu => upu.PromotionId)
                    .OnDelete(DeleteBehavior.Cascade); // Nếu Promotion bị xóa, lịch sử sử dụng của nó cũng bị xóa
            });

            // --- Relationships for Photo ---
            // KHÔNG CÒN CẤU HÌNH Photo - User (người upload) NỮA
            // builder.Entity<Photo>()
            //     .HasOne(p => p.User)
            //     .WithMany()
            //     .HasForeignKey(p => p.UserId)
            //     .OnDelete(DeleteBehavior.Restrict);

            // --- Relationships for Category ---
            builder.Entity<Category>()
               .HasOne(c => c.ParentCategory)
               .WithMany(c => c.ChildCategories)
               .HasForeignKey(c => c.ParentCategoryId)
               .IsRequired(false)
               .OnDelete(DeleteBehavior.Restrict);

            // --- CẤU HÌNH CHO OperatingHour ---
            builder.Entity<OperatingHour>(entity =>
            {
                // Mối quan hệ với Restaurant
                entity.HasOne(oh => oh.Restaurant)
                    .WithMany(r => r.OperatingHours) // Restaurant có ICollection<OperatingHour>
                    .HasForeignKey(oh => oh.RestaurantId)
                    .OnDelete(DeleteBehavior.Cascade); // Khi Restaurant bị xóa, các OperatingHour của nó cũng bị xóa.

                // Bạn có thể thêm Index nếu cần, ví dụ:
                // entity.HasIndex(oh => new { oh.RestaurantId, oh.DayOfWeek });
            });

            // --- Many-to-Many Join Tables (Giữ nguyên) ---
            builder.Entity<MenuItemCategory>(entity =>
            {
                entity.HasKey(mc => new { mc.MenuItemId, mc.CategoryId });
                entity.HasOne(mc => mc.MenuItem)
                    .WithMany(m => m.MenuItemCategories)
                    .HasForeignKey(mc => mc.MenuItemId)
                    .OnDelete(DeleteBehavior.Cascade);
                entity.HasOne(mc => mc.Category)
                    .WithMany(c => c.MenuItemCategories)
                    .HasForeignKey(mc => mc.CategoryId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<RestaurantCuisine>(entity =>
            {
                entity.HasKey(rc => new { rc.RestaurantId, rc.CuisineTypeId });
                entity.HasOne(rc => rc.Restaurant)
                    .WithMany(r => r.RestaurantCuisines)
                    .HasForeignKey(rc => rc.RestaurantId)
                    .OnDelete(DeleteBehavior.Cascade);
                entity.HasOne(rc => rc.CuisineType)
                    .WithMany(ct => ct.Restaurants)
                    .HasForeignKey(rc => rc.CuisineTypeId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<RestaurantTag>(entity =>
            {
                entity.HasKey(rt => new { rt.RestaurantId, rt.TagId });
                entity.HasOne(rt => rt.Restaurant)
                    .WithMany(r => r.RestaurantTags)
                    .HasForeignKey(rt => rt.RestaurantId)
                    .OnDelete(DeleteBehavior.Cascade);
                entity.HasOne(rt => rt.Tag)
                    .WithMany(t => t.RestaurantTags)
                    .HasForeignKey(rt => rt.TagId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<PromotionApplicableItem>()
                .HasKey(pai => new { pai.PromotionId, pai.MenuItemId });

            builder.Entity<PromotionApplicableCategory>()
                .HasKey(pai => new { pai.PromotionId, pai.CategoryId });

            builder.Entity<UserPromotionUsage>()
                .HasKey(pai => new { pai.PromotionId, pai.UserId });
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            
            // Configure query splitting to improve performance with multiple includes
            // Configure query splitting to improve performance with multiple includes
            if (optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer(options => 
                    options.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery));
            }
        }
    }
}