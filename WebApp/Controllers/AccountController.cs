using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NETCore.Encrypt.Extensions;
using System.Resources;
using System.Security.Claims;
using WebApp.Entities;
using WebApp.Models;

namespace WebApp.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly DatabaseContext _databaseContext;
        private readonly IConfiguration _configuration;

        public AccountController(DatabaseContext databaseContext, IConfiguration configuration)
        {
            _databaseContext = databaseContext;
            _configuration = configuration;
        }
        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                string md5Salt = _configuration.GetValue<string>("AppSettings:MD5Salt");
                string saltedPassword = model.Password + md5Salt;
                string hashedPassword = saltedPassword.MD5();

                User user = _databaseContext.Users.SingleOrDefault(x=> x.UserName.ToLower() == model.UserName.ToLower() && x.Password==hashedPassword);

                if (user!=null)
                {
                    if (user.Locked)
                    {
                        ModelState.AddModelError(nameof(model.UserName), "User is locked");
                        return View(model);
                    }

                    List<Claim> claims = new List<Claim>();
                    claims.Add(new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()));
                    claims.Add(new Claim(ClaimTypes.Name,user.FullName ?? string.Empty));
                    claims.Add(new Claim(ClaimTypes.Role,user.Role));
                    claims.Add(new Claim("UserName",user.UserName));


                    ClaimsIdentity identity = new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme);

                    ClaimsPrincipal principal = new ClaimsPrincipal(identity);

                    HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,principal);

                    return RedirectToAction("Index","Home");
                }
                else
                {
                    ModelState.AddModelError("","Username or password is incorrect");
                }
            }
            return View(model);
        }

        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (_databaseContext.Users.Any(x=> x.UserName.ToLower()== model.UserName.ToLower()))
                {
                    ModelState.AddModelError(nameof(model.UserName), "Username is already exist.");
                    return View(model);
                }


                string md5Salt = _configuration.GetValue<string>("AppSettings:MD5Salt");
                string saltedPassword = model.Password + md5Salt;
                string hashedPassword = saltedPassword.MD5();

                User user = new()
                {
                    UserName = model.UserName,
                    Password = hashedPassword
                };
                _databaseContext.Users.Add(user);
                int affectedRowCount = _databaseContext.SaveChanges();

                if (affectedRowCount == 0)
                {
                    ModelState.AddModelError("", "User can not be added.");
                }
                else
                {
                    return RedirectToAction(nameof(Login));
                }

            }
            return View(model);
        }

        public IActionResult Profile()
        {
            return View();
        }



        public IActionResult Logout()
        {
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction(nameof(Login));
        }

    }
}
