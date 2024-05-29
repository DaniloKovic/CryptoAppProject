using CryptoAppProject.Model;
using CryptoAppProject.Model.Requests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace CryptoAppProject.Services
{
    public interface ICryptoService
    {
        // Task GenerateCaCertificateAndKeys();
        X509Certificate GenerateUserCertificate(AsymmetricCipherKeyPair userKeyPair, X509Certificate caCertificate, AsymmetricCipherKeyPair caKeyPair, UserRegistrationRequest userRequest);
        Task<AsymmetricCipherKeyPair> GenerateRsaKeyPair();
        // Task<X509Certificate?> LoadCaCertificate();
        // Task LoadCaKeys();
        // Task LoadCaCertificateAndKeys();
        X509Certificate GetCaCertificate();
        AsymmetricCipherKeyPair GetCaKeys();
        Task SaveUserKeysAndCertificate(AsymmetricCipherKeyPair userKeyPair, 
                                        X509Certificate userCertificate, 
                                        string userPrivateKeyPath, 
                                        string userPublicKeyPath, 
                                        string userCertificatePath);
        Task<PasswordInformations> HashPasswordFunc(string password);
    }
}
