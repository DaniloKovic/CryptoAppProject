using CryptoAppProject.Model.Requests;
using Org.BouncyCastle.Tls;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoAppProject.Helper
{
    public static class CryptoExtensionsClass
    {
        public static async Task<Tuple<string, byte[]>> HashPasswordFunction(string password)
        {
            if (password == null) 
            {
                return new Tuple<string, byte[]>(string.Empty, new byte[32]);
            }
            // Generisanje salta
            byte[] saltBytes = GenerateSalt();

            // Hashiranje lozinke saltom
            string hashedPassword = HashPassword(password, saltBytes);
            return new Tuple<string, byte[]>(hashedPassword, saltBytes);
        }

        private static byte[] GenerateSalt()
        {
            byte[] salt = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        public static string HashPassword(string password, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                // Kombinacija lozinke i soli prije heširanja
                byte[] combinedBytes = Encoding.UTF8.GetBytes(password).Concat(salt).ToArray();
                byte[] hashBytes = sha256.ComputeHash(combinedBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        public static void CreateDigitalCertificateAndKeys(string folderPath, string publicKeyPath, string privateKeyPath, string digitalCertificatePath, bool isForUser, UserRegistrationRequest userRequest = null)
        {
            if (string.IsNullOrEmpty(folderPath) || string.IsNullOrEmpty(publicKeyPath) || string.IsNullOrEmpty(privateKeyPath) || string.IsNullOrEmpty(digitalCertificatePath))
            {
                return;
            }
            // Generiši RSA ključeve za CA tijelo
            using (RSA rsa = RSA.Create())
            {
                // Generiši CA sertifikat
                X509Certificate2 caCertificate = GenerateCACertificate(rsa);
                // Sačuvaj CA sertifikat
                if (!File.Exists($"{folderPath}/{digitalCertificatePath}.cer"))
                {
                    File.WriteAllBytes($"{folderPath}/{digitalCertificatePath}.cer", caCertificate.Export(X509ContentType.Cert));
                }
                
                // Sačuvaj privatni ključ CA tijela
                if (!File.Exists($"{folderPath}/{privateKeyPath}.key"))
                {
                    File.WriteAllText($"{folderPath}/{privateKeyPath}.key", rsa.ToXmlString(true));
                }

                // Sačuvaj javni ključ CA tijela 
                if (!File.Exists($"{folderPath}/{publicKeyPath}.key"))
                {
                    File.WriteAllText($"{folderPath}/{publicKeyPath}.key", rsa.ToXmlString(false));
                }
            }
        }

        private static X509Certificate2 GenerateCACertificate(RSA rsa)
        {
            // Kreiraj CA sertifikat
            var request = new System.Security.Cryptography.X509Certificates
                                .CertificateRequest("CN=CA_Entity", 
                                                    rsa, 
                                                    HashAlgorithmName.SHA256, 
                                                    RSASignaturePadding.Pkcs1);

            // Dodaj dodatne informacije o CA sertifikatu
            // Postavi da je CA sertifikat i da može izdavati druge sertifikate
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); 

            // Postavi period važenja sertifikata
            DateTimeOffset startDate = DateTimeOffset.UtcNow;
            DateTimeOffset endDate = startDate.AddYears(1);

            // Generiši CA sertifikat
            X509Certificate2 caCertificate = request.CreateSelfSigned(
                new DateTimeOffset(startDate.Year, startDate.Month, startDate.Day, 0, 0, 0, TimeSpan.Zero),
                new DateTimeOffset(endDate.Year, endDate.Month, endDate.Day, 23, 59, 59, TimeSpan.Zero));

            return caCertificate;
        }

        public static void CreateDigitalCertificateAndKeysForUser(UserRegistrationRequest newUser, string publicKeyPath, string privateKeyPath, string digitalCertificatePath)
        {
            if (string.IsNullOrEmpty(publicKeyPath) || string.IsNullOrEmpty(privateKeyPath) || string.IsNullOrEmpty(digitalCertificatePath))
            {
                return;
            }
            string caPrivateKeyPath = Path.Combine("CA", "CA_PrivateKey.key");

            using (RSA rsaUser = RSA.Create())
            {
                // Učitaj privatni ključ CA tijela
                using (RSA rsaCA = RSA.Create())
                {
                    rsaCA.ImportRSAPrivateKey(File.ReadAllBytes(caPrivateKeyPath), out _);

                    // Generiši zahtev za sertifikat za korisnika
                    var request = new System.Security.Cryptography.X509Certificates
                                        .CertificateRequest(
                                            $"CN={newUser.Username}", // Common Name korisnika
                                            rsaUser,
                                            HashAlgorithmName.SHA256,
                                            RSASignaturePadding.Pkcs1);

                    // Postavi period važenja sertifikata
                    DateTimeOffset startDate = DateTimeOffset.UtcNow;
                    DateTimeOffset endDate = startDate.AddYears(1);

                    // Generiši sertifikat
                    X509Certificate2 userCertificate = request.Create(
                        issuerName: new X500DistinguishedName("CN=CA_Tijelo"), // Common Name CA tijela
                        notBefore: startDate,
                        notAfter: endDate,
                        signingkey: rsaCA,
                        PublicKey: rsaUser);

                    // Sačuvaj sertifikat u fajl ili koristi ga kako je potrebno
                    string userCertificatePath = "Korisnik_sertifikat.pfx";
                    File.WriteAllBytes(userCertificatePath, userCertificate.Export(X509ContentType.Pfx, "password"));

                    Console.WriteLine($"Sertifikat za korisnika je kreiran i sačuvan na putanji: {userCertificatePath}");
                }
            }
        }

        private static X509Certificate2 GenerateCertificate(RSA rsa, string subjectName, bool isCA = false)
        {
            System.Security.Cryptography.X509Certificates.CertificateRequest? request = new System.Security.Cryptography.X509Certificates
                    .CertificateRequest(subjectName,
                                        rsa,
                                        HashAlgorithmName.SHA256,
                                        RSASignaturePadding.Pkcs1);
            // Postavi period važenja sertifikata
            DateTimeOffset startDate = DateTimeOffset.UtcNow;
            DateTimeOffset endDate = startDate.AddYears(1);


            if (isCA == true)
            {
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                // Generiši CA sertifikat
                X509Certificate2 caCertificate = request.CreateSelfSigned(
                    new DateTimeOffset(startDate.Year, startDate.Month, startDate.Day, 0, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(endDate.Year, endDate.Month, endDate.Day, 23, 59, 59, TimeSpan.Zero));
            }
            else
            {

            }
        }

        public static void ReadExistingCertificate(string digitalCertificatePath)
        {
            try
            {
                //Create X509Certificate2 object from .cer file.
                string filePath = @"C:\Users\Lenovo\source\repos\CryptoAppProject\CryptoAppProject\CA\CA_DigitalCertificate.cer";
                byte[] rawData = ReadFile(filePath);

                X509Certificate2 x509 = new X509Certificate2(rawData);
                // x509.Import(rawData);

                //Print to console information contained in the certificate.
                Console.WriteLine("{0}Subject: {1}{0}", Environment.NewLine, x509.Subject);
                Console.WriteLine("{0}Issuer: {1}{0}", Environment.NewLine, x509.Issuer);
                Console.WriteLine("{0}Version: {1}{0}", Environment.NewLine, x509.Version);
                Console.WriteLine("{0}Valid Date: {1}{0}", Environment.NewLine, x509.NotBefore);
                Console.WriteLine("{0}Expiry Date: {1}{0}", Environment.NewLine, x509.NotAfter);
                Console.WriteLine("{0}Thumbprint: {1}{0}", Environment.NewLine, x509.Thumbprint);
                Console.WriteLine("{0}Serial Number: {1}{0}", Environment.NewLine, x509.SerialNumber);
                Console.WriteLine("{0}Friendly Name: {1}{0}", Environment.NewLine, x509.PublicKey.Oid.FriendlyName);
                Console.WriteLine("{0}Public Key Format: {1}{0}", Environment.NewLine, x509.PublicKey.EncodedKeyValue.Format(true));
                Console.WriteLine("{0}Raw Data Length: {1}{0}", Environment.NewLine, x509.RawData.Length);
                Console.WriteLine("{0}Certificate to string: {1}{0}", Environment.NewLine, x509.ToString(true));
                Console.WriteLine("{0}Certificate to XML String: {1}{0}", Environment.NewLine, x509.PublicKey.Key.ToXmlString(false));

                //Add the certificate to a X509Store.
                X509Store store = new X509Store();
                store.Open(OpenFlags.MaxAllowed);
                store.Add(x509);
                store.Close();
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("Error: The directory specified could not be found.");
            }
            catch (IOException)
            {
                Console.WriteLine("Error: A file in the directory could not be accessed.");
            }
            catch (NullReferenceException)
            {
                Console.WriteLine("File must be a .cer file. Program does not have access to that type of file.");
            }
        }

        private static byte[] ReadFile(string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }
    }
}
