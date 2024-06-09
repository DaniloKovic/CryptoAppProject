namespace CryptoAppProject.Model
{
    public class JwtSettings
    {
        public string? Key { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }        
        public string? Subject { get; set; }

        public override bool Equals(object? obj)
        {
            return obj is JwtSettings settings &&
                   Key == settings.Key &&
                   Issuer == settings.Issuer &&
                   Audience == settings.Audience &&
                   Subject == settings.Subject;
        }

        // public int AccessTokenExpiration { get; set; } // in minutes
        // public string? RefreshTokenSecretKey { get; set; }
        // public int RefreshTokenExpiration { get; set; } // in days
    }
}
