namespace CryptoAppProject.Services.Interface
{
    public interface IBaseAlgorithm
    {
        string Encrypt(string text, string key);
        string Decrypt(string text, string key);
    }
}
