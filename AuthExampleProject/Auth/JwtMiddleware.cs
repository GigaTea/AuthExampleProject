using AuthExampleProject.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthExampleProject.Auth
{
    public class AuthTokenRequest
    {
        public string username { get; set; }
        public string password { get; set; }
        public string grant_type = "password";

        public string FormRequest()
        {
            return "username:" + username + "%password:" + password;
        }
    }

    public class AuthTokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }

    public class JwtMiddleware : ITokenService
    {
        private readonly RequestDelegate _next;

        private IOptions<AppConfigModel> _appSettings;

        public JwtMiddleware(IOptions<AppConfigModel> config)
        {
            _appSettings = config;
        }

        public JwtMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, IOptions<AppConfigModel> config)
        {
            var token = context.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer", "");
            _appSettings = config;

            if (!String.IsNullOrEmpty(token))
                attachUserToContext(context, token);

            await _next(context);
        }

        public void attachUserToContext(HttpContext context, string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Value.AppJobKey);

                tokenHandler.ValidateToken(token, new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    //add other validation properties here
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;

                //check identity claims here for authorization

                context.User.Identities.FirstOrDefault().AddClaims(jwtToken.Claims);
            }
            catch
            {
                //handle it
            }
        }

        public AuthTokenResponse Authenticate(AuthTokenRequest model)
        {
            //access user service to verify user record even exists
            var user = userService.GetUser(model.username);

            if (user == null) return null;

            //perform normal authentication via service with username + password
            var result = authService.Authenticate(model.username, model.password);

            if (result == null || result.StatusCode != "200") return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Value.AppJobKey);

            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim("role", "user"));
            //add more claims as necessary

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenOut = tokenHandler.WriteToken(token);

            return new AuthTokenResponse()
            {
                AccessToken = tokenOut,
                ExpiresIn = 1,
                TokenType = "Bearer"
            };
        }
    }
}
