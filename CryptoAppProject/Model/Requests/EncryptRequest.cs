using CryptoAppProject.Model.Enums;
using System.ComponentModel.DataAnnotations;

namespace CryptoAppProject.Model.Requests
{
    public class EncryptRequest
    {
        [Required]
        public string PlainText { get; set; }
        
        [Required]
        public CryptoAlgorithmEnum Algorithm { get; set; }

        [Required]
        public string Key { get; set; }
    }
}