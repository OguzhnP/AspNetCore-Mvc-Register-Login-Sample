using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebApp.Entities
{
    [Table("Users")]
    public class User
    {
        [Key]
        public Guid Id{ get; set; }
        [StringLength(50)]
        public string? FullName { get; set; }
        [Required]
        [StringLength(30)]
        public string UserName { get; set; }
        [Required]
        [StringLength(200)]
        public string Password { get; set; }
        public bool Locked { get; set; } = false;

        public DateTime CreatedAt { get; set; } = DateTime.Now;

        [Required]
        [StringLength(50)]
        public string Role { get; set; } = "user"; 


    }
}
