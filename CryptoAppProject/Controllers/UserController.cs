﻿using CryptoAppProject.Model.Requests;
using CryptoAppProject.Model;
using CryptoAppProject.Repository.RepositoryInterfaces;
using Microsoft.AspNetCore.Mvc;
using CryptoAppProject.Helper;
using System.Net;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using CryptoAppProject.Model.Response;
using System.Configuration;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1.X9;

namespace CryptoAppProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<UserController> _logger;
        private IUserRepository _userRepository;
        private IConfiguration _configuration;

        public UserController(ILogger<UserController> logger, IUserRepository userRepository, IHttpContextAccessor httpContextAccessor, IConfiguration iConfig)
        {
            _logger = logger;
            _userRepository = userRepository;
            _httpContextAccessor = httpContextAccessor;
            _configuration = iConfig;
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
            Tuple<string, byte[]> passwordInfo = await CryptoExtensionsClass.HashPasswordFunction(userRequest.Password);

            // Check if CA_Entity is existing
            var isCAexist = _configuration.GetSection("MySettings").GetSection("IsExistingCA_Entity").Value;
            var isEstablishedCA = _configuration.GetValue<bool>("MySettings:IsExistingCA_Entity");
            if (!isEstablishedCA)
            {
                // Create CA_Entity.
                // Create Digital certificate for CA_Entity and public/private key for CA_Entity using RSA.
                // For each of keys, create separate files inside CA folder
                const string folderPath = "CA";
                const string caPublicKey = "CA_PublicKey";
                const string caPrivateKey = "CA_PrivateKey";
                const string caDigitalCertificatePath = "CA_DigitalCertificate";
                CryptoExtensionsClass.CreateDigitalCertificateAndKeys("CA", caPublicKey, caPrivateKey, caDigitalCertificatePath, false);
            }

            // Kreiraj digitalni sertifikat i par ključeva za korisnika koji želi da se registruje
            const string userFolderPath = "DigitalCertificates";
            const string userPublicKey = "CA_PublicKey";
            const string userPrivateKey = "CA_PrivateKey";
            const string userDigitalCertificatePath = "CA_DigitalCertificate";
            CryptoExtensionsClass.CreateDigitalCertificateAndKeys(userFolderPath, userPublicKey, userPrivateKey, userDigitalCertificatePath, true, userRequest);

            // Kreiraj digitalni sertifikat i par ključeva za korisnika koji želi da se registruje
            CryptoExtensionsClass.CreateDigitalCertificateAndKeysForUser(userRequest, userPublicKey, userPrivateKey, userDigitalCertificatePath);

            // Insert u bazu

            // Par RSA ključeva koji su povezani sa userom. Public key se stavlja u Dig.Sert., a privatni ključ se vraća nazad korisniku
            using (RSA rsaKey = RSA.Create())
            {
                User newUser = new User()
                {
                    Username = userRequest.Username,
                    PasswordHash = passwordInfo.Item1,
                    Salt = passwordInfo.Item2,
                    Email = userRequest.Email,
                    DateOfRegistration = DateTime.Now,
                    DigitalCertificatePath = $"DigitalCertificates/{userRequest.Username}.pfx",
                    PublicKey = Convert.ToBase64String(rsaKey.ExportSubjectPublicKeyInfo())
                    // PublicKey = "ana"
                };

                // rsaKey.privateKey
                int result = await _userRepository.InsertNewItemAsync(newUser);
                if (result == 1)
                {
                    CertificateRequest? request = new CertificateRequest(
                                                        $"CN={newUser.Username}",
                                                        rsaKey,
                                                        HashAlgorithmName.SHA256,
                                                        RSASignaturePadding.Pkcs1);

                    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
                    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

                    DateTimeOffset startDate = DateTimeOffset.UtcNow;
                    DateTimeOffset endDate = startDate.AddYears(1);

                    X509Certificate2 certificate = request.CreateSelfSigned(new DateTimeOffset(startDate.Year, startDate.Month, startDate.Day, 0, 0, 0, TimeSpan.Zero),
                                                                            new DateTimeOffset(endDate.Year, endDate.Month, endDate.Day, 23, 59, 59, TimeSpan.Zero));

                    // Digitalni sertifikat u PFX fajlu (možete izabrati drugi format po potrebi)
                    // System.IO.File.WriteAllBytes($"DigitalCertificates/{newUser.Username}.pfx", certificate.Export(X509ContentType.Pfx, $"{newUser.PasswordHash}"));
                    System.IO.File.WriteAllBytes($"DigitalCertificates/{newUser.Username}.pfx", certificate.Export(X509ContentType.Pfx, $"{newUser.PasswordHash}"));
                    UserRegistrationResponse response = new UserRegistrationResponse()
                    {
                        PublicKeyBytes = rsaKey.ExportSubjectPublicKeyInfo(),
                        PublicKeyBase64 = Convert.ToBase64String(rsaKey.ExportSubjectPublicKeyInfo()),
                        PrivateKeyBytes = rsaKey.ExportRSAPrivateKey(),
                        PrivateKeyBase64 = Convert.ToBase64String(rsaKey.ExportRSAPrivateKey()),
                        DigitalCertificateFilePath = $"DigitalCertificates/{newUser.Username}.pfx",
                    };
                    return Ok(response);
                }
                else
                {
                    return BadRequest();
                }
            }
        }

        /* Username: kova  Password: kova123 */
        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<HttpStatusCode>> LogInUserAction([FromBody] UserBaseRequest userRequest)
        {
            var user = await _userRepository.GetByUsername(userRequest.Username);
            if (user == null)
            {
                return BadRequest("Invalid credentials! Please, try again!");
            }
            bool result = await _userRepository.LogInUserCheck(userRequest.Username, userRequest.Password);
            if (result == true) 
            {
                UserSessionData loggedUserData = new UserSessionData
                {
                    Username = userRequest.Username,
                    Password = userRequest.Password,    
                };
                _httpContextAccessor.HttpContext?.Session.SetString("UserData", JsonConvert.SerializeObject(loggedUserData));
                return Ok(result);
            }
            return BadRequest(result);
            
        }

        //[HttpPut]
        //public async Task<ActionResult<User>> UpdateUser([FromBody] UserRegistrationRequest userRequest)
        //{
        //    var userToUpdate = await _userRepository.GetByUsername(userRequest.Username);
        //    if (userToUpdate == null)
        //    {
        //        return BadRequest();
        //    }

        //    userToUpdate.Username = userRequest.Username;
        //    userToUpdate.PasswordHash = userRequest.Password;

        //    var result = await _userRepository.UpdateItemAsync(userToUpdate);
        //    return Ok(result);
        //}
    }
}
