using System.ComponentModel.DataAnnotations;

namespace CryptoAppProject.Model.Requests
{
    public class LoginRequest : UserBaseRequest
    {
        [Required]
        public IFormFile Certificate { get; set; }
    }
}