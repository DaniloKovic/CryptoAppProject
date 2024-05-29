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
using CryptoAppProject.Helper;
using CryptoAppProject.Model.Requests;
using CryptoAppProject.Model;

namespace CryptoAppProject.Services
{
    public class CryptoService : ICryptoService
    {
        private const string CaCertificatePath = "CA/ca-certificate.pem";
        private const string CaPrivateKeyPath = "CA/ca-private-key.pem";
        private const string CaPublicKeyPath = "CA/ca-public-key.pem";

        public AsymmetricCipherKeyPair CaKeyPair { get; private set; }
        public X509Certificate CaCertificate { get; private set; }

        public CryptoService() 
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
        }

        private void GenerateCaKeys()
        {
            // Generate RSA key pair for CA
            this.CaKeyPair = CreateRsaKeyPair();
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

        public X509Certificate GetCaCertificate()
        {
            // Load CA certificate and keys from files
            X509Certificate? CaCertificate;
            using (var reader = new StreamReader(CaCertificatePath))
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
    }
}
