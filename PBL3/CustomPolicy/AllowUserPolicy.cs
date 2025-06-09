using Microsoft.AspNetCore.Authorization;
 
namespace PBL3.CustomPolicy
{
    public class AllowUserPolicy : IAuthorizationRequirement
    {
        public string[] AllowUsers { get; set; }
 
        public AllowUserPolicy(params string[] users)
        {
            AllowUsers = users;
        }
    }
}