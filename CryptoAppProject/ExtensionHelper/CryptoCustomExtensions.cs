using CryptoAppProject.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace CryptoAppProject.ExtensionHelper
{
    public static class CryptoCustomExtensions
    {
        public static string HashPassword(string password, byte[] salt)
        {
            // SHA256 heš funkcija
            using (var sha256 = SHA256.Create())
            {
                // Kombinacija lozinke i soli prije heširanja
                byte[] combinedBytes = Encoding.UTF8.GetBytes(password).Concat(salt).ToArray();
                byte[] hashBytes = sha256.ComputeHash(combinedBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        public static string GenerateAccessToken(User user, IConfiguration configuration)
        {
            var nowUtc = DateTime.UtcNow;
            var expirationDuration = TimeSpan.FromMinutes(15);
            var expirationUtc = nowUtc.Add(expirationDuration);

            List<Claim> claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, configuration["JwtSecurityToken:Subject"]),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(nowUtc).ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp,EpochTime.GetIntDate(expirationUtc).ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Iss, configuration["JwtSecurityToken:Issuer"]),
                new Claim(JwtRegisteredClaimNames.Aud, configuration["JwtSecurityToken:Audience"]),
                new Claim("Id", user.Id.ToString()),
                new Claim("Username", user.Username),
            };

            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwtSecurityToken:Key"]));
            SigningCredentials signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: configuration["JwtSecurityToken:Issuer"],
                audience: configuration["JwtSecurityToken:Audience"],
                claims: claims,
                // notBefore: nowUtc,
                expires: expirationUtc,
                signingCredentials: signIn);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenString = tokenHandler.WriteToken(token);

            // bool isValid = ValidateJwtToken(tokenString, configuration);

            return tokenString;
        }

        private static bool ValidateJwtToken(string token, IConfiguration configuration)
        {
            try
            {
                var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                var res = jwtSecurityTokenHandler.ValidateToken(
                            token,
                            new TokenValidationParameters
                            {
                                ValidateIssuer = true,
                                ValidateAudience = false,
                                ValidateLifetime = false,
                                ValidateIssuerSigningKey = true,
                                ValidIssuer = configuration["JwtSecurityToken:Issuer"],
                                ValidAudience = configuration["JwtSecurityToken:Audience"],
                                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwtSecurityToken:Key"]))
                            },
                            out SecurityToken validatedToken
                        );
            }
            catch (Exception e)
            {
                string message = e.Message;
                return false;
            }
            return true;
        }

        //public static string GenerateRefreshToken(JwtSettings jwtSettings)
        //{
        //    byte[]? refreshKey = Encoding.ASCII.GetBytes(jwtSettings.RefreshTokenSecretKey);
        //    using (var rng = RandomNumberGenerator.Create())
        //    {
        //        rng.GetBytes(refreshKey);
        //        return Convert.ToBase64String(refreshKey);
        //    }
        //}

        //public static void SetTokenCookie(string refreshToken)
        //{
        //    var cookieOptions = new CookieOptions
        //    {
        //        HttpOnly = true,
        //        Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiration)
        //    };
        //    Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        //}
    }
}
