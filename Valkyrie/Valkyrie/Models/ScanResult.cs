using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Valkyrie.Models
{
    public enum ScanStatus
    {
        Completed,
        PartialFailure,
        Failed
    }

    public class ScanResult
    {
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; } = null!;

        // Navigation property for the User
        public IdentityUser User { get; set; } = null!;

        [Required]
        public string RepositoryUrl { get; set; } = null!;

        [Required]
        public string RepositoryName { get; set; } = null!;

        public string? EcosystemsDetected { get; set; }

        public string? SecurityGrade { get; set; }

        public int TotalIssuesFound { get; set; }

        public DateTime ScannedAt { get; set; }

        public ScanStatus Status { get; set; }

        // Navigation properties
        public ICollection<VulnerablePackage> VulnerablePackages { get; set; } = new List<VulnerablePackage>();
        
        public ICollection<CodeIssue> CodeIssues { get; set; } = new List<CodeIssue>();
    }
}
