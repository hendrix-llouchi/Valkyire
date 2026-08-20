using System.ComponentModel.DataAnnotations;

namespace Valkyrie.Models
{
    public enum Ecosystem
    {
        Npm,
        NuGet,
        Python,
        Maven,
        Go,
        Ruby,
        PHP
    }

    public enum Severity
    {
        Critical,
        High,
        Medium,
        Low
    }

    public class VulnerablePackage
    {
        public int Id { get; set; }

        public int ScanResultId { get; set; }

        // Navigation property back to ScanResult
        public ScanResult ScanResult { get; set; } = null!;

        [Required]
        public string PackageName { get; set; } = null!;

        public Ecosystem Ecosystem { get; set; }

        public string? InstalledVersion { get; set; }

        public string? SafeVersion { get; set; }

        public Severity Severity { get; set; }

        public string? Description { get; set; }

        public string? AiExplanation { get; set; }

        public string? AiFixSuggestion { get; set; }
    }
}
