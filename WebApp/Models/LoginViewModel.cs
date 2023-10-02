using System.ComponentModel.DataAnnotations;

namespace WebApp.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Username alanı zorunludur")]
        [StringLength(30, ErrorMessage = "En fazla 30 karakter olabilir.")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password alanı zorunludur")]
        [MinLength(6, ErrorMessage = "Minumum 6 karakter olmalıdır.")]
        [MaxLength(15, ErrorMessage = "Maksimum 15 karakter olmalıdır.")]
        //[DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
