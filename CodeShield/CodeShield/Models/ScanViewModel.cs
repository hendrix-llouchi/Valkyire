using System.Collections.Generic;

namespace CodeShield.Models
{
    public class ScanViewModel
    {
        public string RepositoryUrl { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
        public List<string>? Files { get; set; }
        public List<DependencyPackage>? Packages { get; set; }
        public List<Ecosystem>? DetectedEcosystems { get; set; }
        public List<CodeIssue>? CodeIssues { get; set; }
        public bool IsSubmitted { get; set; }
        public string? OsvWarningMessage { get; set; }
    }
}
