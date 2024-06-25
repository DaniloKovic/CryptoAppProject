using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography;
using CryptoAppProject.ExtensionHelper;
using CryptoAppProject.Model.Requests;
using CryptoAppProject.Model;
using CryptoAppProject.Model.Response;
using CryptoAppProject.Model.Enums;
using CryptoAppProject.Services.Interface;
using System.Text;
// using System.Security.Cryptography.X509Certificates;

namespace CryptoAppProject.Services.Implementation
{
    public class CryptoService : ICryptoService
    {
        private readonly IServiceProvider _serviceProvider;

        private const string CaCertificatePath = "CA/ca-certificate.pem";
        private const string CaPrivateKeyPath = "CA/ca-private-key.pem";
        private const string CaPublicKeyPath = "CA/ca-public-key.pem";

        public AsymmetricCipherKeyPair CaKeyPair { get; private set; }
        public X509Certificate CaCertificate { get; private set; }

        public CryptoService(IServiceProvider serviceProvider)
        {
            // Load CA certificate and keys from files
            if (File.Exists(CaPrivateKeyPath) && File.Exists(CaPrivateKeyPath) && File.Exists(CaCertificatePath))
            {
                CaCertificate = LoadCertificate(CaCertificatePath);

                AsymmetricKeyParameter? caPublickKey = LoadCaPublicKey(CaPublicKeyPath);
                AsymmetricCipherKeyPair? caPrivateKey = LoadCaPrivateKey(CaPrivateKeyPath);
                CaKeyPair = new AsymmetricCipherKeyPair(caPublickKey, caPrivateKey?.Private);
            }
            else
            {
                GenerateCaKeys();
                GenerateCaCertificate();
            }
            _serviceProvider = serviceProvider;
        }

        private void GenerateCaKeys()
        {
            // Generate RSA key pair for CA
            CaKeyPair = CreateRsaKeyPair();
            SaveKey(CaKeyPair.Private, CaPrivateKeyPath);
            SaveKey(CaKeyPair.Public, CaPublicKeyPath);
        }

        private void GenerateCaCertificate()
        {
            // Generate RSA key pair for CA
            CaKeyPair = CreateRsaKeyPair();

            // Save CA keys
            SaveKey(CaKeyPair.Private, CaPrivateKeyPath);
            SaveKey(CaKeyPair.Public, CaPublicKeyPath);

            // Generate self-signed CA certificate
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom());
            X509V3CertificateGenerator caCertificateGenerator = new X509V3CertificateGenerator();
            caCertificateGenerator.SetSerialNumber(serialNumber);
            caCertificateGenerator.SetIssuerDN(new X509Name("CN=CryptoAppCA"));
            caCertificateGenerator.SetSubjectDN(new X509Name("CN=CryptoAppCA"));
            caCertificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            caCertificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(5)); // Valid for 5 years
            caCertificateGenerator.SetPublicKey(CaKeyPair.Public);
            // caCertificateGenerator.SignatureAlgNames("SHA256WithRSAEncryption");

            // Add basic constraints for CA
            caCertificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            caCertificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            caCertificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(CaKeyPair.Public));
            caCertificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(CaKeyPair.Public));

            // Use Asn1SignatureFactory for setting the signature algorithm
            CaCertificate = caCertificateGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", CaKeyPair.Private));

            // Save CA certificate
            SaveCertificate(CaCertificate, CaCertificatePath);
        }

        private void SaveCertificate(X509Certificate certificate, string path)
        {
            using (var writer = new StreamWriter(path))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(certificate);
            }
        }

        private X509Certificate LoadCertificate(string path)
        {
            // Load CA certificate 
            using (var reader = new StreamReader(path))
            {
                PemReader pemReader = new PemReader(reader);
                return pemReader.ReadObject() as X509Certificate;
            }
        }

        public X509Certificate GetCaCertificate(string path = null)
        {
            // Load CA certificate and keys from files
            X509Certificate? CaCertificate;

            path = string.IsNullOrEmpty(path) ? CaCertificatePath : path;
            using (var reader = new StreamReader(path))
            {
                PemReader pemReader = new PemReader(reader);
                CaCertificate = pemReader.ReadObject() as X509Certificate;
            }
            return CaCertificate;
        }

        public AsymmetricCipherKeyPair GetCaKeys()
        {
            return CaKeyPair;
        }

        private AsymmetricKeyParameter? LoadCaPublicKey(string path)
        {
            using (var reader = new StreamReader(path))
            {
                var pemReader = new PemReader(reader);
                if (path.Contains("public"))
                {
                    AsymmetricKeyParameter publicCaKey = (AsymmetricKeyParameter)pemReader.ReadObject();
                    return publicCaKey;
                }
            }
            return null;
        }

        private AsymmetricCipherKeyPair? LoadCaPrivateKey(string path)
        {
            using (var reader = new StreamReader(path))
            {
                var pemReader = new PemReader(reader);
                if (path.Contains("private"))
                {
                    AsymmetricCipherKeyPair privateCaKey = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    return privateCaKey;
                }
            }
            return null;
        }

        private void SaveKey(AsymmetricKeyParameter key, string path)
        {
            EnsureDirectoryExists(Path.GetDirectoryName(path));
            using (var writer = new StreamWriter(path))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(key);
            }
        }

        public async Task<PasswordInformations> HashPasswordFunc(string password)
        {
            if (password == null)
            {
                return new PasswordInformations();
            }

            // Generisanje salta
            byte[] saltBytes = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(saltBytes);
            }

            // Hashiranje lozinke saltom
            string hashedPassword = CryptoCustomExtensions.HashPassword(password, saltBytes);
            return new PasswordInformations()
            {
                HashedPassword = hashedPassword,
                Salt = saltBytes
            };
        }

        public async Task<AsymmetricCipherKeyPair> GenerateRsaKeyPair()
        {
            AsymmetricCipherKeyPair rsaKeyPair = CreateRsaKeyPair();
            return rsaKeyPair;
        }

        private AsymmetricCipherKeyPair CreateRsaKeyPair()
        {
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair rsaKeyPair = keyPairGenerator.GenerateKeyPair();
            return rsaKeyPair;
        }

        public X509Certificate GenerateUserCertificate(AsymmetricCipherKeyPair userKeyPair, X509Certificate caCertificate, AsymmetricCipherKeyPair caKeyPair, UserRegistrationRequest userRequest)
        {
            var userCertificateGenerator = new X509V3CertificateGenerator();

            userCertificateGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new SecureRandom()));
            userCertificateGenerator.SetIssuerDN(caCertificate.SubjectDN);
            userCertificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            userCertificateGenerator.SetNotBefore(DateTime.UtcNow);
            userCertificateGenerator.SetSubjectDN(new X509Name($"CN={userRequest.Username}"));
            userCertificateGenerator.SetPublicKey(userKeyPair.Public);
            // userCertificateGenerator.SetSignatureAlgorithm("SHA256WithRSAEncryption");

            // Basic constraints for end user certificate
            userCertificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            userCertificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));

            return userCertificateGenerator.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", CaKeyPair.Private));
        }

        public async Task SaveUserKeysAndCertificate(AsymmetricCipherKeyPair userKeyPair, X509Certificate userCertificate, string userPrivateKeyPath, string userPublicKeyPath, string userCertificatePath)
        {
            SaveKey(userKeyPair.Private, userPrivateKeyPath);
            SaveKey(userKeyPair.Public, userPublicKeyPath);
            SaveCertificate(userCertificate, userCertificatePath);
        }

        private void EnsureDirectoryExists(string path)
        {
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
        }

        public Task<BaseResponse> ValidateCertificate(string path)
        {
            if (!File.Exists(path) || !path.Contains(".pem"))
            {
                return Task.FromResult(new BaseResponse()
                {
                    Message = "Invalid path!",
                    Success = false
                });
            }
            X509Certificate cert = LoadCertificate(path);
            return Task.FromResult(new BaseResponse()
            {
                Message = "Valid!",
                Success = true
            });
        }


        public X509Certificate ReadCertificate(string path)
        {
            using (var reader = File.OpenText(path))
            {
                var pemReader = new PemReader(reader);
                var certificate = (X509Certificate)pemReader.ReadObject();
                return certificate;
            }
        }

        public bool ValidateCertificate(X509Certificate userCertificate, string username, X509Certificate caCertificate)
        {
            try
            {
                userCertificate.Verify(caCertificate.GetPublicKey());

                // Provera da li sertifikat pripada korisniku
                var certificateSubject = userCertificate.SubjectDN.ToString();
                if (!certificateSubject.Contains($"CN={username}"))
                {
                    return false;
                }
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<string> Encrypt(string directoryPath, string plainText, CryptoAlgorithmEnum algorithm, string key, string username)
        {
            string encryptedText = string.Empty;
            try
            {
                IBaseAlgorithm cryptoAlgorithm = GetCryptoAlgorithm(algorithm);
                encryptedText = cryptoAlgorithm.Encrypt(plainText, key);
                SaveFiles(directoryPath, plainText, algorithm, key, encryptedText, username);
            }
            catch(Exception ex) 
            {
                return ex.Message;
            }
            return encryptedText;
        }

        private IBaseAlgorithm GetCryptoAlgorithm(CryptoAlgorithmEnum algorithm)
        {
            return algorithm switch
            {
                CryptoAlgorithmEnum.RailFence => _serviceProvider.GetService<IRailFenceService>(),
                CryptoAlgorithmEnum.Myszkowski => _serviceProvider.GetService<IMyszkowskiService>(),
                CryptoAlgorithmEnum.Playfair => _serviceProvider.GetService<IPlayfairService>(),
                _ => throw new ArgumentException("Unsupported algorithm")
            };
        }

        private void SaveFiles(string directoryPath, string plainText, CryptoAlgorithmEnum algorithm, string key, string encryptedText, string username)
        {
            try
            {
                string filePath = $"{directoryPath}/encrypted.txt";
                string filePathHashed = $"{directoryPath}/encryptedHashed.txt";

                // Load AES key
                byte[] aesKey = LoadAESKey($"{directoryPath}/{username}-aes.key");

                // tekstual content to add 
                string newEntry = $"{plainText} | {algorithm.ToString()} | {key} | {encryptedText}{Environment.NewLine}";

                // Step 1: Read and decrypt existing content
                string existingContent = "";
                if (File.Exists(filePath))
                {
                    byte[] encryptedContent = File.ReadAllBytes(filePath);
                    existingContent = DecryptWithAes(encryptedContent, aesKey);
                }

                // Step 2: Add new entry to the existing content
                string updatedContent = existingContent + newEntry;

                // Step 3: Encrypt updated content
                byte[] encryptedUpdatedContent = EncryptWithAes(updatedContent, aesKey);

                // Step 4: Write encrypted updated content back to the file
                File.WriteAllBytes(filePath, encryptedUpdatedContent);

                byte[] newFileContent = File.ReadAllBytes(filePath);
                using (var sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(newFileContent);
                    File.WriteAllBytes(filePathHashed, hashBytes);
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        private string CalculateHash(string content)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private string EncryptString(string plainText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.GenerateIV();
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream())
                    {
                        ms.Write(aes.IV, 0, aes.IV.Length);
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            using (var sw = new StreamWriter(cs))
                            {
                                sw.Write(plainText);
                            }
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }

        private string DecryptString(string cipherText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] buffer = Convert.FromBase64String(cipherText);
                using (var ms = new MemoryStream(buffer))
                {
                    byte[] iv = new byte[16];
                    ms.Read(iv, 0, iv.Length);
                    aes.Key = Encoding.UTF8.GetBytes(key);
                    aes.IV = iv;
                    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var sr = new StreamReader(cs))
                            {
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }

        public async Task<string> Decrypt(string text, CryptoAlgorithmEnum algorithm, string key)
        {
            return string.Empty;
        }

        public Task GenerateAndSaveAESKey(string userAesKeyPath)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256; // Set the key size to 256 bits
                    aes.GenerateKey();
                    byte[] aesKeyBytes = aes.Key;
                    File.WriteAllBytes(userAesKeyPath, aesKeyBytes);
                }
                return Task.CompletedTask;
            }
            catch (Exception ex) 
            {
                throw ex;
            }
        }

        private byte[] LoadAESKey(string userAesKeyPath)
        {
            try
            {
                byte[] aesKeyBytes = File.ReadAllBytes(userAesKeyPath);
                return aesKeyBytes;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<string> ReadAlgorithmSimulationFile(string filePath, string fileHashPath, string aesKeyPath)
        {
            try
            {
                string fileContent = await VerifyFileIntegrityAsync(filePath, fileHashPath, aesKeyPath);
                return fileContent;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private async Task<string> VerifyFileIntegrityAsync(string filePath, string fileHashPath, string aesKeyPath)
        {
            try
            {
                byte[] aesKey = LoadAESKey(aesKeyPath);

                byte[] encryptedContent = File.ReadAllBytes(filePath);
                string decryptedContent = DecryptWithAes(encryptedContent, aesKey);

                using (var sha256 = SHA256.Create())
                {
                    byte[] computedHash = sha256.ComputeHash(encryptedContent);
                    byte[] storedHash = File.ReadAllBytes(fileHashPath);

                    // Uporedi heš vrednosti
                    if (computedHash.SequenceEqual(storedHash))
                    {
                        return decryptedContent;
                    }
                }
                return "Detected change on encrypted.txt";
            }
            catch (Exception ex)
            {
                return "An error occurred while verifying the file integrity. " + ex.Message;
            }
        }

        private byte[] EncryptWithAes(string plainText, byte[] aesKey)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.GenerateIV();
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream())
                    {
                        // Write IV to the beginning of the memory stream
                        ms.Write(aes.IV, 0, aes.IV.Length);
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        using (var sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }

        private string DecryptWithAes(byte[] cipherText, byte[] aesKey)
        {
            using (Aes aesAlg = Aes.Create())
            {
                using (var ms = new MemoryStream(cipherText))
                {
                    // Read the IV from the beginning of the stream
                    byte[] iv = new byte[aesAlg.IV.Length];
                    ms.Read(iv, 0, iv.Length);

                    aesAlg.Key = aesKey;
                    aesAlg.IV = iv;
                    using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }
}
