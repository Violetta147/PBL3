using PBL3.Models;
using Microsoft.AspNetCore.Identity;

namespace PBL3.IdentityPolicy
{
    public class CustomUsernameEmailPolicy : UserValidator<AppUser>
    {
        public override async Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
        {
            IdentityResult result = await base.ValidateAsync(manager, user);
            List<IdentityError> errors = result.Succeeded ? new List<IdentityError>() : result.Errors.ToList();

            if (user.UserName == "google")
            {
                errors.Add(new IdentityError
                {
                    Description = "Google cannot be used as a user name"
                });
            }

            if (user.Email != null)
            {
                string emailDomain = user.Email.Substring(user.Email.LastIndexOf('@') + 1).ToLower();
                string[] allowedDomains = { "gmail.com", "yahoo.com", "outlook.com", "icloud.com", "hotmail.com", "live.com" }; // Danh sách domain bạn cho phép

                if (!allowedDomains.Contains(emailDomain))
                {
                    errors.Add(new IdentityError
                    {
                        Code = "InvalidEmailDomain",
                        Description = $"Email domain '@{emailDomain}' is not allowed. Allowed domains are: {string.Join(", ", allowedDomains)}"
                    });
                }
            }

            return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
        }
    }
}