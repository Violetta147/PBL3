using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using PBL3.Models;

namespace PBL3.Controllers;

public class HomeController : Controller
{
    private readonly SignInManager<AppUser> _signInManager;
    private readonly UserManager<AppUser> _userManager;
    public HomeController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)] //?
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
    [Authorize(Roles="Manager")]
    public async Task<IActionResult> Secured()
    {
        AppUser user = await _userManager.GetUserAsync(HttpContext.User);
        string message = "Hello " + user.UserName;
        return View((object)message);
    }

    [HttpGet] // Quan trọng: Nên là GET vì nó chỉ điều hướng hoặc hiển thị
    public IActionResult HandleLootYourBusiness()
    {
        if (_signInManager.IsSignedIn(User))
        {
            return RedirectToAction("MyRestaurants", "Business");
        }
        else
        {
            string returnUrl = Url.Action("MyRestaurants", "Business");
            TempData["ShowLoginModal"] = "true";
            TempData["LoginReturnUrl"] = Url.Action("MyRestaurants", "Business");

            return RedirectToAction("Index", "Home");
        }
    }
}
