using System.ComponentModel.DataAnnotations;

namespace CryptoAppProject.Model.Requests
{
    public class LoginRequest : UserBaseRequest
    {
        [Required]
        public string CertificatePath { get; set; }
    }
}