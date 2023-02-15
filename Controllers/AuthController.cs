using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestApi.Models;

namespace TestApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration) 
        {
            _configuration = configuration;
        }
        [HttpPost("register")]
        public ActionResult<User> register(UserDto reguest)
        {
            string PasswordHash = BCrypt.Net.BCrypt.HashPassword(reguest.Password); 
            user.Username = reguest.Username;
            user.PasswordHash = PasswordHash;
            return Ok(user);

        }

        [HttpPost("login")]
        public ActionResult<User> login(UserDto reguest)
        {
           if(user.Username!= reguest.Username)
            {
                return BadRequest("User not found");
            }

           if(!BCrypt.Net.BCrypt.Verify(reguest.Password , user.PasswordHash))
            {
                return BadRequest("Wrong password. ");
            }
            string token = Creatrtoken(user); 
            return Ok(token);
        }

        private string Creatrtoken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSetting:Token").Value!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims : claims,
                expires : DateTime.Now.AddDays(1),
                signingCredentials : creds
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    } 
}