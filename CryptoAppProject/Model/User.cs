﻿// <auto-generated> This file has been auto generated by EF Core Power Tools. </auto-generated>
#nullable disable
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace CryptoAppProject.Model;

[Table("user")]
[Index("DigitalCertificatePath", Name = "DigitalCertificatePath_UNIQUE", IsUnique = true)]
[Index("Username", Name = "Username_UNIQUE", IsUnique = true)]
public partial class User
{
    [Key]
    [Column("ID")]
    public int Id { get; set; }

    [Required]
    [StringLength(50)]
    public string Username { get; set; }

    [Required]
    [StringLength(255)]
    public string PasswordHash { get; set; }

    [Required]
    [MaxLength(32)]
    public byte[] Salt { get; set; }

    [Required]
    [StringLength(100)]
    public string Email { get; set; }

    [Column(TypeName = "datetime")]
    public DateTime DateOfRegistration { get; set; }

    [Required]
    public string DigitalCertificatePath { get; set; }

    [Required]
    public string PublicKey { get; set; }

    [InverseProperty("User")]
    public virtual ICollection<LogActivity> LogActivities { get; set; } = new List<LogActivity>();
}