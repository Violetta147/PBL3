// Data/Seeders/RoleAndUserSeeder.cs
using Microsoft.AspNetCore.Identity;
using PBL3.Models;
using System;
using System.Globalization; // Cần cho CompareInfo và CompareOptions
using System.Linq;
using System.Text; // Cần cho StringBuilder
using System.Text.RegularExpressions; // Cần cho Regex
using System.Threading.Tasks;

namespace PBL3.Data.Seeder
{
    public static class RoleAndUserSeeder
    {
        private static readonly Random _random = new Random(); // Khai báo _random ở đây

        // Hàm RemoveDiacritics (ví dụ, bạn có thể có hàm tốt hơn)
        public static string RemoveDiacritics(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return text;

            text = text.Normalize(NormalizationForm.FormD);
            var sb = new StringBuilder();

            foreach (char ch in text)
            {
                UnicodeCategory uc = CharUnicodeInfo.GetUnicodeCategory(ch);
                if (uc != UnicodeCategory.NonSpacingMark)
                {
                    sb.Append(ch);
                }
            }
            // Chuyển thành chữ thường và loại bỏ khoảng trắng, ký tự đặc biệt không mong muốn
            string result = sb.ToString().Normalize(NormalizationForm.FormC).ToLower();
            result = Regex.Replace(result, @"\s+", ""); // Loại bỏ tất cả khoảng trắng
            result = Regex.Replace(result, @"[^a-z0-9]", ""); // Chỉ giữ lại chữ cái thường và số
            return result;
        }


        public static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            string[] roleNames = { "Admin", "User" };
            foreach (var roleName in roleNames)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }
        }

        public static async Task SeedAdminUsersAsync(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            await SeedRolesAsync(roleManager);

            string adminEmail = "admin@gmail.com";
            string adminPassword = "Password@223";
            string adminDisplayName = "Quản Trị Viên";
            // Tạo UserName từ DisplayName
            string adminUserName = RemoveDiacritics(adminDisplayName);
            if (string.IsNullOrWhiteSpace(adminUserName)) // Phòng trường hợp DisplayName không tạo ra UserName hợp lệ
            {
                adminUserName = "admin" + _random.Next(100, 999); // Tạo một UserName dự phòng
            }


            if (await userManager.FindByNameAsync(adminUserName) == null && await userManager.FindByEmailAsync(adminEmail) == null)
            {
                var adminUser = new AppUser
                {
                    UserName = adminUserName, // Sử dụng UserName đã xử lý
                    Email = adminEmail,
                    DisplayName = adminDisplayName,
                    EmailConfirmed = true,
                    PhoneNumber = "0123456789",
                    PhoneNumberConfirmed = true,
                    CreatedAt = new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    UpdatedAt = new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    AvatarUrl = null,
                    AvatarCloudinaryPublicId = null
                };
                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                }
                else
                {
                    Console.WriteLine($"Lỗi khi tạo admin '{adminEmail}': {string.Join(", ", result.Errors.Select(e => e.Description))}");
                }
            }
        }

        public static async Task SeedBasicUsersAsync(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            await SeedRolesAsync(roleManager);

            string[] firstNamesMale = { "Nguyễn Văn", "Trần Minh", "Lê Hoàng", "Phạm Đức", "Võ Tuấn", "Đặng Quốc", "Bùi Gia", "Đỗ Thành", "Hồ Anh" };
            string[] firstNamesFemale = { "Nguyễn Thị", "Trần Ngọc", "Lê Phương", "Phạm Thu", "Hoàng Thanh", "Võ Mai", "Đặng Kim", "Bùi Diệu", "Đỗ Bảo", "Hồ Quỳnh" };
            string[] lastNamesMale = { "An", "Bảo", "Dũng", "Hải", "Hiếu", "Hoàng", "Huy", "Khánh", "Khoa", "Long", "Mạnh", "Minh", "Nam", "Nghĩa", "Phát", "Phong", "Phúc", "Quân", "Quang", "Sơn", "Tài", "Thắng", "Thành", "Thiên", "Thông", "Trung", "Tuấn", "Tùng", "Việt", "Vinh" };
            string[] lastNamesFemale = { "Anh", "Bích", "Châu", "Chi", "Diệp", "Dung", "Giang", "Hà", "Hân", "Hạnh", "Hoa", "Hồng", "Huệ", "Hương", "Khánh", "Kim", "Lan", "Linh", "Ly", "Mai", "My", "Nga", "Ngân", "Ngọc", "Nhi", "Như", "Phương", " Quỳnh", "Thảo", "Thi", "Thơ", "Thúy", "Thủy", "Tiên", "Trà", "Trang", "Trinh", "Trúc", "Tú", "Tuyền", "Uyên", "Vân", "Vy", "Xuân", "Yến" };
            string[] emailDomains = { "gmail.com", "yahoo.com", "outlook.com", "icloud.com", "hotmail.com", "live.com" };

            var usersToSeedInfo = new List<(string Email, string DisplayName, string PhoneNumber, GenderType? Gender, DateTime? DateOfBirth, string UserName)>();

            for (int i = 0; i < 70; i++)
            {
                string firstName, lastName, displayName, email, phoneNumber, userNameBase;
                GenderType? gender;
                DateTime? dateOfBirth;
                bool isMaleAssignedForName;

                int genderRoll = _random.Next(1, 21);
                if (genderRoll <= 9) { gender = GenderType.Male; isMaleAssignedForName = true; }
                else if (genderRoll <= 18) { gender = GenderType.Female; isMaleAssignedForName = false; }
                else { gender = GenderType.Other; isMaleAssignedForName = _random.Next(0, 2) == 0; }

                if (isMaleAssignedForName)
                {
                    firstName = firstNamesMale[_random.Next(firstNamesMale.Length)];
                    lastName = lastNamesMale[_random.Next(lastNamesMale.Length)];
                }
                else
                {
                    firstName = firstNamesFemale[_random.Next(firstNamesFemale.Length)];
                    lastName = lastNamesFemale[_random.Next(lastNamesFemale.Length)];
                }

                displayName = $"{firstName} {lastName}";
                userNameBase = RemoveDiacritics(displayName); // Tạo UserName từ DisplayName đã xử lý

                string emailLastName = RemoveDiacritics(lastName).ToLower();
                string emailFirstNamePart = RemoveDiacritics(firstName).ToLower().Replace(" ", "");
                if (emailFirstNamePart.Length > 5) emailFirstNamePart = emailFirstNamePart.Substring(0, 5);

                int yearOfBirth = _random.Next(1970, 2006);
                int monthOfBirth = _random.Next(1, 13);
                int dayOfBirth = _random.Next(1, DateTime.DaysInMonth(yearOfBirth, monthOfBirth) + 1);
                dateOfBirth = new DateTime(yearOfBirth, monthOfBirth, dayOfBirth);

                email = $"{emailLastName}{emailFirstNamePart}{i:D2}@{emailDomains[_random.Next(emailDomains.Length)]}"; // Thêm i để tăng tính duy nhất
                email = email.Replace("..", ".").Replace(" ", "");

                string[] phonePrefixes = { "090", "091", "093", "094", "096", "097", "098", "086", "088", "032", "033", "034", "035", "036", "037", "038", "039", "070", "079", "077", "076" };
                phoneNumber = $"{phonePrefixes[_random.Next(phonePrefixes.Length)]}{_random.Next(1000000, 9999999):D7}";

                usersToSeedInfo.Add((email, displayName, phoneNumber, gender, dateOfBirth, userNameBase));
            }

            string defaultUserPassword = "UserPass@373"; // Đảm bảo mật khẩu này đủ mạnh

            foreach (var userInfo in usersToSeedInfo)
            {
                string finalUserName = userInfo.UserName;
                int attempt = 0;
                // Kiểm tra và tạo UserName duy nhất
                while (await userManager.FindByNameAsync(finalUserName) != null)
                {
                    attempt++;
                    finalUserName = $"{userInfo.UserName}{attempt}";
                }

                if (await userManager.FindByEmailAsync(userInfo.Email) == null)
                {
                    var user = new AppUser
                    {
                        UserName = finalUserName, // Sử dụng UserName duy nhất
                        Email = userInfo.Email,
                        DisplayName = userInfo.DisplayName,
                        EmailConfirmed = true,
                        PhoneNumber = userInfo.PhoneNumber,
                        PhoneNumberConfirmed = _random.Next(0, 3) != 0, // 2/3 là confirmed
                        Gender = userInfo.Gender,
                        DateOfBirth = userInfo.DateOfBirth,
                        CreatedAt = DateTime.UtcNow.AddDays(-_random.Next(1, 365)), // Ngày tạo ngẫu nhiên trong năm qua
                        UpdatedAt = DateTime.UtcNow.AddDays(-_random.Next(0, 90)), // Cập nhật trong 3 tháng qua (phải sau CreatedAt)
                        AvatarUrl = null,
                        AvatarCloudinaryPublicId = null
                    };

                    // Đảm bảo UpdatedAt không trước CreatedAt
                    if (user.UpdatedAt < user.CreatedAt) user.UpdatedAt = user.CreatedAt;


                    var result = await userManager.CreateAsync(user, defaultUserPassword);
                    if (result.Succeeded)
                    {
                        await userManager.AddToRoleAsync(user, "User");
                    }
                    else
                    {
                        Console.WriteLine($"Lỗi khi tạo user '{userInfo.Email}' với UserName '{finalUserName}': {string.Join(", ", result.Errors.Select(e => e.Description))}");
                    }
                }
                else
                {
                    Console.WriteLine($"Email '{userInfo.Email}' đã tồn tại, bỏ qua việc tạo user.");
                }
            }
        }
    }
}