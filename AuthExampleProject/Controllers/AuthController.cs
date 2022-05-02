using AuthExampleProject.Auth;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthExampleProject.Controllers
{
    public class AuthController : Controller
    {

        private ITokenService _tokenService;
        public AuthController(ITokenService tokenService)
        {
            _tokenService = tokenService;
        }

        [HttpPost("token")]
        public IActionResult Authenticate(AuthTokenRequest model)
        {
            var response = _tokenService.Authenticate(model);

            if (response == null)
                return BadRequest(new { message = "Username or password incorrect" });

            return Ok(JsonConvert.SerializeObject(response));
        }
    }
}
