using System;
using System.Net;
using System.Net.Mail;
using System.Text.Encodings.Web; // Cho HtmlEncoder
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration; // Để đọc cấu hình từ appsettings.json
using Microsoft.Extensions.Logging; // (Tùy chọn) Để ghi log

namespace PBL3.Ultilities
{
    public interface IEmailSender // (Tùy chọn) Tạo interface để dễ dàng thay thế hoặc mock
    {
        Task<bool> SendEmailConfirmationAsync(string userEmail, string confirmationLink);
        Task<bool> SendEmailTwoFactorCodeAsync(string userEmail, string code);
        Task<bool> SendEmailPasswordResetAsync(string userEmail, string resetLink);
        Task<bool> SendGenericEmailAsync(string toEmail, string subject, string htmlMessage); // Phương thức chung
    }

    public class EmailHelper : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailHelper> _logger; // (Tùy chọn)

        private readonly string _smtpHost;
        private readonly int _smtpPort;
        private readonly string _smtpUser;
        private readonly string _smtpPass;
        private readonly string _fromEmail;
        private readonly string _fromName;
        private readonly bool _enableSsl;

        public EmailHelper(IConfiguration configuration, ILogger<EmailHelper> logger = null) // logger là tùy chọn
        {
            _configuration = configuration;
            _logger = logger;

            // Đọc cài đặt SMTP từ configuration. Cung cấp giá trị mặc định nếu không tìm thấy.
            _smtpHost = _configuration["SmtpSettings:Host"] ?? "smtp.gmail.com";
            _smtpPort = int.TryParse(_configuration["SmtpSettings:Port"], out int port) ? port : 587;
            _smtpUser = _configuration["SmtpSettings:Username"] ?? throw new ArgumentNullException("SmtpSettings:Username not configured.");
            _smtpPass = _configuration["SmtpSettings:Password"] ?? throw new ArgumentNullException("SmtpSettings:Password not configured.");
            _fromEmail = _configuration["SmtpSettings:FromEmail"] ?? _smtpUser;
            _fromName = _configuration["SmtpSettings:FromName"] ?? "Your Application";
            _enableSsl = bool.TryParse(_configuration["SmtpSettings:EnableSsl"], out bool ssl) ? ssl : true;
        }

        public async Task<bool> SendGenericEmailAsync(string toEmail, string subject, string htmlMessage)
        {
            if (string.IsNullOrEmpty(toEmail) || string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(htmlMessage))
            {
                _logger?.LogError("SendGenericEmailAsync: toEmail, subject, or htmlMessage is null or empty.");
                return false;
            }

            try
            {
                using (MailMessage mailMessage = new MailMessage())
                {
                    mailMessage.From = new MailAddress(_fromEmail, _fromName);
                    mailMessage.To.Add(new MailAddress(toEmail));
                    mailMessage.Subject = subject;
                    mailMessage.Body = htmlMessage;
                    mailMessage.IsBodyHtml = true;

                    using (SmtpClient smtpClient = new SmtpClient(_smtpHost, _smtpPort))
                    {
                        smtpClient.Credentials = new NetworkCredential(_smtpUser, _smtpPass);
                        smtpClient.EnableSsl = _enableSsl;
                        // smtpClient.Timeout = 20000; // 20 giây (tùy chọn)

                        await smtpClient.SendMailAsync(mailMessage);
                        _logger?.LogInformation("Email sent successfully to {ToEmail} with subject '{Subject}'.", toEmail, subject);
                    }
                }
                return true;
            }
            catch (SmtpException smtpEx)
            {
                _logger?.LogError(smtpEx, "SmtpException while sending email to {ToEmail} with subject '{Subject}'. StatusCode: {StatusCode}", toEmail, subject, smtpEx.StatusCode);
                // Bạn có thể muốn ném lại một exception cụ thể hơn hoặc xử lý dựa trên StatusCode
                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Generic Exception while sending email to {ToEmail} with subject '{Subject}'.", toEmail, subject);
                return false;
            }
        }

        public async Task<bool> SendEmailConfirmationAsync(string userEmail, string confirmationHtmlLink)
        {
            string subject = "Xác nhận địa chỉ email của bạn";
            // confirmationHtmlLink đã là HTML, ví dụ: $"Vui lòng xác nhận tài khoản... <a href='...'>nhấn vào đây</a>."
            return await SendGenericEmailAsync(userEmail, subject, confirmationHtmlLink);
        }

        public async Task<bool> SendEmailTwoFactorCodeAsync(string userEmail, string code)
        {
            string subject = "Mã xác thực hai yếu tố của bạn";
            // Sử dụng HtmlEncoder để đảm bảo code không bị hiểu nhầm là HTML nếu nó chứa ký tự đặc biệt
            string body = $"Mã xác thực hai yếu tố của bạn là: <strong>{HtmlEncoder.Default.Encode(code)}</strong>";
            return await SendGenericEmailAsync(userEmail, subject, body);
        }

        public async Task<bool> SendEmailPasswordResetAsync(string userEmail, string resetHtmlLink)
        {
            string subject = "Yêu cầu đặt lại mật khẩu";
            // resetHtmlLink đã là HTML, ví dụ: $"Vui lòng đặt lại mật khẩu... <a href='...'>nhấn vào đây</a>."
            return await SendGenericEmailAsync(userEmail, subject, resetHtmlLink);
        }
    }
}