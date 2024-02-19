namespace CryptoAppProject.Model.Response
{
    public class UserRegistrationResponse
    {
        public string? DigitalCertificateFilePath { get; set; }
        public string? PublicKeyBase64 { get; set; }
        public byte[]? PublicKeyBytes { get; set; }
        public string? PrivateKeyBase64 { get; set; }
        public byte[]? PrivateKeyBytes { get; set; }

        public string? PublicKeyCA { get; set; }
        public byte[]? PublicKeyCABytes { get; set; }
    }
}
