using System.Net.Mail;
 
namespace PBL3.Ultilities
{
    public class EmailHelper
    {
        // other methods
 
        public bool SendEmailTwoFactorCode(string userEmail, string code)
        {
            MailMessage mailMessage = new MailMessage();
            mailMessage.From = new MailAddress("nguyenhuuminhquan147@gmail.com"); //
            mailMessage.To.Add(new MailAddress(userEmail));
 
            mailMessage.Subject = "Two Factor Code";
            mailMessage.IsBodyHtml = true;
            mailMessage.Body = $"Your OTP is: <strong>{code}</strong>";
 
            SmtpClient client = new SmtpClient();
            client.Credentials = new System.Net.NetworkCredential("nguyenhuuminhquan147@gmail.com", "zrnl lupc neix rlmm");
            client.Host = "smtp.gmail.com";
            client.Port = 587;
            client.EnableSsl = true;
 
            try
            {
                client.Send(mailMessage);
                return true;
            }
            catch (Exception ex)
            {
                // log exception
            }
            return false;
        }
        //Mail Confirmation
        //The Two action methods kinda the same
        public bool SendEmail(string userEmail, string confirmationLink)
        {
            MailMessage mailMessage = new MailMessage();
            mailMessage.From = new MailAddress("nguyenhuuminhquan147@gmail.com");
            mailMessage.To.Add(new MailAddress(userEmail));
 
            mailMessage.Subject = "Confirm your email";
            mailMessage.IsBodyHtml = true;
            mailMessage.Body = confirmationLink;
 
            SmtpClient client = new SmtpClient();
            client.Credentials = new System.Net.NetworkCredential("nguyenhuuminhquan147@gmail.com", "zrnl lupc neix rlmm");
            client.Host = "smtp.gmail.com";
            client.Port = 587;
 
            try
            {
                client.Send(mailMessage);
                return true;
            }
            catch (Exception ex)
            {
                // log exception
            }
            return false;
        }
    }
}