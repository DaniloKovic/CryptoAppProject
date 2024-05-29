using CryptoAppProject.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace CryptoAppProject.Helper
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

        public static string GenerateAccessToken(User user, JwtSettings jwtSettings)
        {
            var key = Encoding.ASCII.GetBytes(jwtSettings.SecretKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Email, user.Email)
                }),
                Expires = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenExpiration),
                Issuer = jwtSettings.Issuer,
                Audience = jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

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
