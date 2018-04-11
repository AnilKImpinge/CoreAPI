using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Newtonsoft.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;

namespace CoreJWTApi.Controllers
{
    [Produces("application/json")]
    [Route("api/AuthV1")]
    public class AuthV1Controller : Controller
    {
        //some config in the appsettings.json  
        private IConfiguration _config;
        public AuthV1Controller(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("auth")]
        public IActionResult Auth([FromBody]Parameters parameters)
        {
            if (parameters == null)
            {
                return Json(new ResponseData
                {
                    Code = "901",
                    Message = "null of parameters",
                    Data = null
                });
            }

            if (parameters.grant_type == "password")
            {
                return Json(DoPassword(parameters));
            }
            else if (parameters.grant_type == "refresh_token")
            {
                return Json(DoRefreshToken(parameters));
            }
            else
            {
                return Json(new ResponseData
                {
                    Code = "904",
                    Message = "bad request",
                    Data = null
                });
            }
        }

        //scenario 1 ï¼š get the access-token by username and password  
        private ResponseData DoPassword(Parameters parameters)
        {
            //validate the client_id/client_secret/username/passwo  
            var isValidated = Users.GetUsers().Any(x => x.client_id == parameters.client_id
                                    && x.client_secret == parameters.client_secret
                                    && x.username == parameters.username
                                    && x.password == parameters.password);

            if (!isValidated)
            {
                return new ResponseData
                {
                    Code = "902",
                    Message = "invalid user infomation",
                    Data = null
                };
            }

            var refresh_token = Guid.NewGuid().ToString().Replace("-", "");

            var rToken = new RToken
            {
                ClientId = parameters.client_id,
                RefreshToken = refresh_token,
                Id = Guid.NewGuid().ToString(),
                IsStop = 0
            };

            //store the refresh_token   
            if (RToken.AddToken(rToken))
            {
                return new ResponseData
                {
                    Code = "999",
                    Message = "OK",
                    Data = GetJwt(parameters.client_id, refresh_token)
                };
            }
            else
            {
                return new ResponseData
                {
                    Code = "909",
                    Message = "can not add token to database",
                    Data = null
                };
            }
        }
        //scenario 2 ï¼š get the access_token by refresh_token  
        private ResponseData DoRefreshToken(Parameters parameters)
        {
            var token = RToken.GetToken(parameters.refresh_token, parameters.client_id);

            if (token == null)
            {
                return new ResponseData
                {
                    Code = "905",
                    Message = "can not refresh token",
                    Data = null
                };
            }

            if (token.IsStop == 1)
            {
                return new ResponseData
                {
                    Code = "906",
                    Message = "refresh token has expired",
                    Data = null
                };
            }

            var refresh_token = Guid.NewGuid().ToString().Replace("-", "");

            token.IsStop = 1;
            //expire the old refresh_token and add a new refresh_token  
            var updateFlag = RToken.ExpireToken(token);

            var addFlag = RToken.AddToken(new RToken
            {
                ClientId = parameters.client_id,
                RefreshToken = refresh_token,
                Id = Guid.NewGuid().ToString(),
                IsStop = 0
            });

            if (updateFlag && addFlag)
            {
                return new ResponseData
                {
                    Code = "999",
                    Message = "OK",
                    Data = GetJwt(parameters.client_id, refresh_token)
                };
            }
            else
            {
                return new ResponseData
                {
                    Code = "910",
                    Message = "can not expire token or a new token",
                    Data = null
                };
            }
        }

        //get the jwt token   
        private object GetJwt(string client_id, string refresh_token)
        {
            var now = DateTime.UtcNow;

            var claims = new Claim[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, client_id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, now.ToUniversalTime().ToString(), ClaimValueTypes.Integer64)
            };

            var keyByteArray = Encoding.ASCII.GetBytes(_config["Jwt:Key"]);
            var signingKey = new SymmetricSecurityKey(keyByteArray);

            var jwt = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims: claims,
                notBefore: now,
                expires: now.Add(TimeSpan.FromMinutes(2)),
                signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256));

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                access_token = encodedJwt,
                expires_in = (int)TimeSpan.FromMinutes(2).TotalSeconds,
                refresh_token = refresh_token,
            };

            return response;
        }
    }

    public class RToken
    {
        public string ClientId { get; set; }
        public string RefreshToken { get; set; }
        public string Id { get; set; }
        public int IsStop { get; set; }
        public static List<RToken> RefreshTokens { get; set; }
        static RToken()
        {
            if (RefreshTokens == null)
            {
                RefreshTokens = new List<RToken>();
            }
        }

        public static bool AddToken(RToken rToken)
        {
            RefreshTokens.Add(rToken);
            return true;
        }

        public static RToken GetToken(string rToken, string clientId)
        {
            return RefreshTokens.FirstOrDefault(x => x.RefreshToken == rToken && x.ClientId == clientId);
        }

        public static bool ExpireToken(RToken token)
        {
            var tokenInfo = RefreshTokens.FirstOrDefault(x => x.Id == token.Id);
            tokenInfo.IsStop = token.IsStop;
            return true;
        }
    }
}

public class Parameters
{
    public string username;
    public string password;
    public string client_secret;
    public string client_id;
    public string refresh_token { get; set; }

    public string grant_type { get; set; }
}

internal class ResponseData
{
    public string Code { get; set; }
    public string Message { get; set; }
    public object Data { get; set; }
}

public class Users
{
    public string username { get; set; }
    public string password { get; set; }
    public string client_secret { get; set; }
    public string client_id { get; set; }
    public static List<Users> GetUsers()
    {
        List<Users> users = new List<Users> {
                new Users { username="test",password="1234",client_id="client123",client_secret="secret" },
                new Users { username="test1",password="1234",client_id="client123",client_secret="secret" },
            };

        return users;
    }
}
