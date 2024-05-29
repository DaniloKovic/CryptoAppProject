using CryptoAppProject.Model.Requests;
using CryptoAppProject.Model;
using CryptoAppProject.Repository.RepositoryInterfaces;
using Microsoft.AspNetCore.Mvc;
using CryptoAppProject.Model.Response;
using CryptoAppProject.Services;
using Microsoft.Extensions.Options;
using CryptoAppProject.Helper;

namespace CryptoAppProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private IUserRepository _userRepository;
        private ILogActivityRepository _logActivityRepository;
        private readonly JwtSettings _jwtSettings;
        private IConfiguration _configuration;
        private readonly ICryptoService _cryptoService;

        public UserController(IUserRepository userRepository, 
                              ILogActivityRepository logActivityRepository,                              
                              IConfiguration iConfig,
                              ICryptoService cryptoService,
                              IOptions<JwtSettings> jwtSettings)
        {
            _logActivityRepository = logActivityRepository;
            _userRepository = userRepository;
            _configuration = iConfig;
            _cryptoService = cryptoService;
            _jwtSettings = jwtSettings.Value;
        }

        [HttpGet(Name = "User")]
        public async Task<ActionResult<List<User>>> GetAllUsers()
        {
            IEnumerable<User> users = await _userRepository.GetAll();
            return Ok(users);
        }

        /* Username: kova  Password: kova123 */
        [HttpPost]
        [Route("Registration")]
        public async Task<ActionResult<UserRegistrationResponse>> RegisterNewUser([FromBody] UserRegistrationRequest userRequest)
        {
            var user = await _userRepository.GetByUsername(userRequest.Username);
            if (user != null)
            {
                return BadRequest("Please choose another username!");
            }
            PasswordInformations passwordInfo = await _cryptoService.HashPasswordFunc(userRequest.Password);

            // Kreiraj par ključeva za korisnika koji želi da se registruje
            var userRsaKeys = await _cryptoService.GenerateRsaKeyPair();

            // Load CA certificate and keys
            var caCertificate = _cryptoService.GetCaCertificate();
            var caKeys = _cryptoService.GetCaKeys();

            // Kreiraj sertifikat za korisnika koji želi da se registruje
            var userCertificate = _cryptoService.GenerateUserCertificate(userRsaKeys, caCertificate, caKeys, userRequest);

            // Save user keys and certificate
            string userFolderPath = $"UserInformations/{userRequest.Username}";
            string userPrivateKeyPath = $"{userFolderPath}/{userRequest.Username}-private-key.pem";
            string userPublicKeyPath = $"{userFolderPath}/{userRequest.Username}-public-key.pem";
            string userDigitalCertificatePath = $"{userFolderPath}/{userRequest.Username}-certificate.pem";
            await _cryptoService.SaveUserKeysAndCertificate(userRsaKeys, 
                                                            userCertificate,
                                                            userPrivateKeyPath, 
                                                            userPublicKeyPath, 
                                                            userDigitalCertificatePath);

            int result = await _userRepository.InsertNewItemAsync(new User()
            {
                Username = userRequest.Username,
                PasswordHash = passwordInfo.HashedPassword,
                Salt = passwordInfo.Salt,
                Email = userRequest.Email,
                DateOfRegistration = DateTime.Now,
                DigitalCertificatePath = userDigitalCertificatePath,
                PublicKey = userPublicKeyPath
            });
            if (result == 1)
            {
                User? createdUser = await _userRepository.GetByUsername(userRequest.Username);
                await _logActivityRepository.InsertNewItemAsync(new LogActivity()
                {
                    UserId = createdUser.Id,
                    Description = $"User registered successfully! {createdUser.Username}, {createdUser.Email}, {createdUser.DateOfRegistration}",
                });
                var response = new UserRegistrationResponse()
                {
                    DigitalCertificateFilePath = userDigitalCertificatePath,
                    PrivateKeyFilePath = userPrivateKeyPath,
                    PublicKeyFilePath = userPublicKeyPath
                };
                return Ok(response);
            }
            return BadRequest();
        }

        /* Username: kova  Password: kova123 */
        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<LoginResponse>> LogInUserAction([FromBody] LoginRequest loginRequest)
        {
            // Validacija digitalnog sertifikata
            if (loginRequest.Certificate == null)
            {
                return BadRequest("Invalid login request. Please provide all required fields.");
            }

            var user = await _userRepository.GetByUsername(loginRequest.Username);
            if (user == null)
            {
                return BadRequest("Invalid credentials! Please, try again!");
            }
            bool result = await _userRepository.LogInUserCheck(loginRequest.Username, loginRequest.Password);
            if (result == true) 
            {
                var accessToken = CryptoCustomExtensions.GenerateAccessToken(user, _jwtSettings);
                var refreshToken = CryptoCustomExtensions.GenerateRefreshToken();

                // Save the refresh token in the user's record in the database here
                SetTokenCookie(refreshToken);
                return Ok(new LoginResponse
                { 
                    Username = loginRequest.Username,
                    // Password = password,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken 
                });
            }
            return BadRequest(result);
        }

        private void SetTokenCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiration)
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        //private string GenerateAccessToken(User user)
        //{
        //    var key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);
        //    var tokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Subject = new ClaimsIdentity(new[]
        //        {
        //            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        //            new Claim(ClaimTypes.Name, user.Username),
        //            new Claim(ClaimTypes.Email, user.Email)
        //        }),
        //        Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiration),
        //        Issuer = _jwtSettings.Issuer,
        //        Audience = _jwtSettings.Audience,
        //        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        //    };
        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var token = tokenHandler.CreateToken(tokenDescriptor);
        //    return tokenHandler.WriteToken(token);
        //}

        //private string GenerateRefreshToken()
        //{
        //    var randomNumber = new byte[32];
        //    using (var rng = RandomNumberGenerator.Create())
        //    {
        //        rng.GetBytes(randomNumber);
        //        return Convert.ToBase64String(randomNumber);
        //    }
        //}


    }
}
