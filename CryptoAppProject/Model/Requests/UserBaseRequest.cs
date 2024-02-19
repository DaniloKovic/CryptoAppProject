using System.ComponentModel.DataAnnotations;

namespace CryptoAppProject.Model.Requests
{
    public class UserBaseRequest
    {
        public UserBaseRequest()
        {
        }

        public UserBaseRequest(string username, string password)
        {
            Username = username;
            Password = password;
        }

        [Required]
        [StringLength(50)]
        public string Username { get; set; }

        [Required]
        [StringLength(255)]
        public string Password { get; set; }

        //public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        //{
        //    if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password))
        //    {
        //        yield return new ValidationResult("Parameters are not valid! Please fill all fields");
        //    }
        //}
    }
}
