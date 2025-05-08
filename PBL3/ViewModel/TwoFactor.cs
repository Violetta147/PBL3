using System.ComponentModel.DataAnnotations;
 
namespace PBL3.ViewModel
{
    public class TwoFactor
    {
        [Required]
        public string TwoFactorCode { get; set; }
    }
}