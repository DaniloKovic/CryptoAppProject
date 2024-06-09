namespace CryptoAppProject.Model.Response
{
    public class LoginResponse : BaseResponse
    {
        public string? Username { get; set; } = string.Empty;
        public string? AccessToken { get; set; }
        // public string? RefreshToken { get; set; }
    }
}
