using Microsoft.AspNetCore.Mvc;

namespace PBL3.Controllers
{
    public class AdminBaseController : Controller
    {
        protected string GetCurrentUserId() => User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    }
}
