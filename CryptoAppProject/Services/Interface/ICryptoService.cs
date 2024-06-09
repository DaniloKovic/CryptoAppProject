using CryptoAppProject.Model;
using CryptoAppProject.Model.Enums;
using CryptoAppProject.Model.Requests;
using CryptoAppProject.Model.Response;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace CryptoAppProject.Services.Interface
{
    public interface ICryptoService
    {
        X509Certificate GenerateUserCertificate(AsymmetricCipherKeyPair userKeyPair, X509Certificate caCertificate, AsymmetricCipherKeyPair caKeyPair, UserRegistrationRequest userRequest);
        Task<AsymmetricCipherKeyPair> GenerateRsaKeyPair();
        X509Certificate GetCaCertificate(string path = null);
        AsymmetricCipherKeyPair GetCaKeys();
        Task SaveUserKeysAndCertificate(AsymmetricCipherKeyPair userKeyPair,
                                        X509Certificate userCertificate,
                                        string userPrivateKeyPath,
                                        string userPublicKeyPath,
                                        string userCertificatePath);
        Task<PasswordInformations> HashPasswordFunc(string password);
        Task<BaseResponse> ValidateCertificate(string path);
        X509Certificate ReadCertificate(string path);
        bool ValidateCertificate(X509Certificate userCertificate, string username, X509Certificate caCertificate);
        Task<string> Encrypt(string directoryPath, string text, CryptoAlgorithmEnum algorithm, string key, string username);
        Task<string> Decrypt(string text, CryptoAlgorithmEnum algorithm, string key);
        Task GenerateAndSaveAESKey(string filePath);
        // byte[] LoadAESKey(string directoryPath);
        Task<string> ReadAlgorithmSimulationFile(string filePath, string fileHashPath);
    }
}
