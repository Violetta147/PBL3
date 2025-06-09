using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PBL3.Data;
using PBL3.Models;
using PBL3.IdentityPolicy;
using PBL3.CustomPolicy;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.Options;
using PBL3.Data.Seeder;
using PBL3.Models.Settings;
using PBL3.Services.Interfaces;
using PBL3.Services.Implementations;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.Configure<CloudinarySettings>(builder.Configuration.GetSection("CloudinarySettings")); 
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(
        connectionString,
        sqlServerOptionsAction: sqlOptions =>
        {
            sqlOptions.MigrationsAssembly("PBL3");
            sqlOptions.MigrationsHistoryTable("__EFMigrationsHistory", "dbo");
            sqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
        }
    );
});
builder.Services.AddIdentity<AppUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
builder.Services.Configure<IdentityOptions>(options =>
{


    options.Password.RequiredLength = 8;            // Minimum password length.
    options.Password.RequireLowercase = true;       // Require at least one lowercase ('a'-'z').
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";


    // Lockout settings (optional but recommended)
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    options.Lockout.MaxFailedAccessAttempts = 3;
});
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(10);
});

builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    // Cấu hình session nếu cần, ví dụ thời gian timeout
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true; // Rất quan trọng, để đảm bảo cookie hoạt động ngay cả khi người dùng chưa đồng ý với chính sách cookie (GDPR)
});

builder.Services.AddTransient<IPasswordValidator<AppUser>, CustomPasswordPolicy>();
builder.Services.AddTransient<IUserValidator<AppUser>, CustomUsernameEmailPolicy>();
builder.Services.AddTransient<IAuthorizationHandler, AllowUsersHandler>();
builder.Services.AddTransient<IAuthorizationHandler, AllowPrivateHandler>();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Home/Index"; // HOẶC "/Identity/Account/Login" nếu bạn có trang login đầy đủ
                                       // HOẶC "/Account/Login" nếu bạn có action Login (GET) trả về View đầy đủ
    options.Cookie.Name = ".AspNetCore.Identity.Application";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
});

builder.Services.AddAuthentication()
        .AddGoogle(opts =>
        {
            IConfigurationSection googleAuthNSection = builder.Configuration.GetSection("Authentication:Google");
            opts.ClientId = googleAuthNSection["ClientId"];
            opts.ClientSecret = googleAuthNSection["ClientSecret"];
            opts.SignInScheme = IdentityConstants.ExternalScheme;
            opts.CallbackPath = new PathString("/signin-google");
        });
builder.Services.AddAuthorization(opts => {
    opts.AddPolicy("AspManager", policy => {
        policy.RequireRole("Manager");
        policy.RequireClaim("Coding-Skill", "ASP.NET Core MVC");
    });
    opts.AddPolicy("AllowTom", policy => {
        policy.AddRequirements(new AllowUserPolicy("tom"));
    });
    opts.AddPolicy("PrivateAccess", policy =>
    {
        policy.AddRequirements(new AllowPrivatePolicy());
    });
});
builder.Services.AddTransient<PBL3.Ultilities.EmailHelper>();

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Add HttpClient for API calls
builder.Services.AddHttpClient();

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
builder.Services.AddTransient<PBL3.Ultilities.IEmailSender, PBL3.Ultilities.EmailHelper>();
builder.Services.AddScoped<IPhotoService, CloudinaryPhotoService>();

builder.Services.AddScoped<IRestaurantService, RestaurantService>();
builder.Services.AddScoped<ICuisineTypeService, CuisineTypeService>();
builder.Services.AddScoped<ITagService, TagService>();
builder.Services.AddScoped<IMenuService, MenuService>();
builder.Services.AddScoped<IReviewService, ReviewService>();
builder.Services.AddScoped<IGeoLocationService, GeoLocationService>();
var app = builder.Build();

// --- GỌI SEEDER Ở ĐÂY ---
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        // LẤY UserManager VÀ RoleManager TỪ services TRONG SCOPE HIỆN TẠI
        var userManager = services.GetRequiredService<UserManager<AppUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

        // // Seed dữ liệu
        // await CuisineTypeSeeder.SeedCuisineTypesAsync(context);
        // await CategorySeeder.SeedAsync(context);
        // await TagSeeder.SeedTagsAsync(context);

        // // Gọi seeder cho Roles và Users
        // await RoleAndUserSeeder.SeedRolesAsync(roleManager); // Gọi riêng để đảm bảo roles được tạo trước
        // await RoleAndUserSeeder.SeedAdminUsersAsync(userManager, roleManager);
        // await RoleAndUserSeeder.SeedBasicUsersAsync(userManager, roleManager);

        // // --- GỌI ADDRESS SEEDER ---
        // await AddressSeeder.SeedAsync(context);

        // await RestaurantSeeder.SeedAsync(context);
        // await MenuSeeder.SeedAsync(context);
        // await RestaurantCuisineSeeder.SeedAsync(context); // SEED RESTAURANT-CUISINE
        // await RestaurantTagSeeder.SeedAsync(context);     // SEED RESTAURANT-TAG
        // await MenuItemCategorySeeder.SeedAsync(context);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseStaticFiles();
app.UseSession();
app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "adminDefault",
    pattern: "{controller=AdminDashboard}/{action=Index}/{id?}"); // Route cho Area

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}"); // Route mặc định

app.MapRazorPages()
   .WithStaticAssets();

app.Run();
