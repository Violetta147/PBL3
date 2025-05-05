using System.ComponentModel.DataAnnotations;

namespace PBL3.ViewModel
{
    public class User
    {
        [Required]
        public string Name { get; set; }

        [Required]
        // [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ErrorMessage = "E-mail is not valid")]
        public string Email { get; set; }

        [Required]
        // [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", ErrorMessage = "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")]
        public string Password { get; set; }
        
    }
    
}