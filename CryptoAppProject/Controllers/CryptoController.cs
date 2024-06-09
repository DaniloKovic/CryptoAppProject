using CryptoAppProject.Model.Requests;
using CryptoAppProject.Model;
using CryptoAppProject.Repository.RepositoryInterfaces;
using Microsoft.AspNetCore.Mvc;
using CryptoAppProject.Model.Response;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;
using CryptoAppProject.Model.Enums;
using CryptoAppProject.Services.Interface;

namespace CryptoAppProject.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class CryptoController : ControllerBase
    {
        private IUserRepository _userRepository;
        private ILogActivityRepository _logActivityRepository;
        private readonly JwtSettings _jwtSettings;
        private readonly ICryptoService _cryptoService;

        public CryptoController(IUserRepository userRepository, 
                                ILogActivityRepository logActivityRepository, 
                                ICryptoService cryptoService,
                                IOptions<JwtSettings> jwtSettings)
        {
            _logActivityRepository = logActivityRepository;
            _userRepository = userRepository;
            _cryptoService = cryptoService;
            _jwtSettings = jwtSettings.Value;
        }

        [HttpGet()]
        [Route("Kova")]
        public async Task<string> GetMyString()
        {
            var userName = User.Identity?.Name;
            return "KovaStrings";
        }

        [HttpPost]
        [Route("Encrypt")]
        public async Task<ActionResult<EncryptResponse>> Encrypt([FromBody] EncryptRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var claims = User.Claims.ToList();
                var userId = User.Claims.FirstOrDefault(c => c.Type == "Id")?.Value;
                // var username = User.Claims.FirstOrDefault(c => c.Type == "Username")?.Value; // Ne radi ?!?
                User? user = await _userRepository.Get(Int32.Parse(userId));
                if (user is null)
                {
                    return BadRequest("Non existing user!");
                }
                string? directoryPath = Path.GetDirectoryName(user?.DigitalCertificatePath).Replace("\\", "/");

                string? encryptedText = await _cryptoService.Encrypt(directoryPath, request.PlainText, request.Algorithm, request.Key, user.Username);
                return Ok(new EncryptResponse()
                {
                    EncryptedText = encryptedText,
                });
            }
            catch (Exception ex) 
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet]
        [Route("SimulationHistory")]
        public async Task<IActionResult> GetSimulationHistory()
        {
            try
            {
                string? userId = User.Claims.FirstOrDefault(c => c.Type == "Id")?.Value;
                User? user = await _userRepository.Get(Int32.Parse(userId));
                if (user is null)
                {
                    return BadRequest("Non existing user!");
                }

                string folderPath = Path.GetDirectoryName(user?.DigitalCertificatePath).Replace("\\", "/");
                string filePath = $"{folderPath}/encrypted.txt";
                string fileHashPath = $"{folderPath}/encryptedHashed.txt";

                string fileContent = await _cryptoService.ReadAlgorithmSimulationFile(filePath, fileHashPath);
                return Ok(fileContent);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Internal server error: " + ex.Message);
            }
        }


    }
}
