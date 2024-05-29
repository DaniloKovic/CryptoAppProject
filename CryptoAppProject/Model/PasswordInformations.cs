namespace CryptoAppProject.Model
{
    public class PasswordInformations
    {
        public string? HashedPassword { get; set; }
        public byte[]? Salt { get; set; }
    }
}
