using System.ComponentModel.DataAnnotations;

namespace Valkyrie.Models
{
    public enum IssueType
    {
        HardcodedSecret,
        SqlInjectionRisk,
        ExposedConfig,
        InsecureHttp
    }

    public class CodeIssue
    {
        public int Id { get; set; }

        public int ScanResultId { get; set; }

        // Navigation property back to ScanResult
        public ScanResult ScanResult { get; set; } = null!;

        [Required]
        public string FileName { get; set; } = null!;

        public int LineNumber { get; set; }

        public IssueType IssueType { get; set; }

        public string? CodeSnippet { get; set; }

        public Severity Severity { get; set; }

        public string? AiExplanation { get; set; }

        public string? AiFixSuggestion { get; set; }
    }
}
