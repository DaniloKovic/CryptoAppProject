using System.ComponentModel.DataAnnotations;

namespace CryptoAppProject.Model.Requests
{
    public class UserRegistrationRequest : UserBaseRequest
    {

        public UserRegistrationRequest(string username, string password, string email) 
            : base(username, password) 
        {
            Email = email;
        }

        [Required]
        [StringLength(100)]
        public string Email { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password) || string.IsNullOrEmpty(Email))
            {
                yield return new ValidationResult("Parameters are not valid! Please fill all fields");
            }
        }
    }
}