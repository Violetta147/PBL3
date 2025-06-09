using Microsoft.AspNetCore.Mvc;
using PBL3.Controllers;

namespace PBL3.Controllers
{
    public class AdminDashboardController : AdminBaseController // Kế thừa
    {
        public IActionResult Index()
        {
            // Logic cho trang dashboard
            return View(); // Sẽ tìm View trong Views/AdminDashboard/Index.cshtml
        }
    }
}
