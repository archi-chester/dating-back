using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using dating_app_api.Data;
using dating_app_api.Dtos;
using dating_app_api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace dating_app_api.Controllers
{
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    // контроллер для аутентификации
    public class AuthController : ControllerBase
    {
        // private
        // экемпляр конфигурации контроллера
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        // конструктор
        public AuthController(IConfiguration config,
            IMapper mapper,
            UserManager<User> userManager,
            SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
            _mapper = mapper;

        }

        // регистрация
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            // создаем сущность под нового пользователя
            var userToCreate = _mapper.Map<User>(userForRegisterDto);

            var result = await _userManager.CreateAsync(userToCreate, userForRegisterDto.Password);

            // возвращаемый объект на фронт
            var userToReturn = _mapper.Map<UserForDetailedDto>(userToCreate);

            if (result.Succeeded)
            {
                // возврашаем статус вновь созданного объекта
                return CreatedAtRoute("GetUser", new { Controller = "Users", id = userToCreate.Id }, userToReturn);
            }

            return BadRequest(result.Errors);

        }

        // логин
        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var user = await _userManager.FindByNameAsync(userForLoginDto.Username);

            var result = await _signInManager.CheckPasswordSignInAsync(user, userForLoginDto.Password, false);

            if (result.Succeeded) 
            {
                var appUser = await _userManager.Users.Include(p => p.Photos)
                    .FirstOrDefaultAsync(u => u.NormalizedUserName == userForLoginDto.Username.ToUpper());
                    
                // связываем пользователя из разных баз
                var userToReturn = _mapper.Map<UserForListDto>(appUser);

                // возвращаем созданный токен со статусом 200
                return Ok(new
                {
                    token = GenerateJwtToken(appUser).Result,
                    user = userToReturn
                });
            }

            return Unauthorized();
        }

        private async Task<string> GenerateJwtToken(User user)
        {
            // создаем клаймс (ID, Name)
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var roles = await _userManager.GetRolesAsync(user);

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // генерим ключ из секрета в файле настроек 
            var key = new SymmetricSecurityKey(Encoding.UTF8
                .GetBytes(_config.GetSection("AppSettings:Token").Value));

            // Генерим на базе ключа креденшнлы 
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // генерим Секьюрити дескриптор токена с временем жизни 1 день
            var tokenDescripter = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            // создаем аготовку для токена
            var tokenHandler = new JwtSecurityTokenHandler();

            // создаем токен на базе дескриптора
            var token = tokenHandler.CreateToken(tokenDescripter);

            return tokenHandler.WriteToken(token);

        }
    }
}