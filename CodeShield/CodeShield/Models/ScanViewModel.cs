using System.Collections.Generic;

namespace CodeShield.Models
{
    public class ScanViewModel
    {
        public string RepositoryUrl { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
        public List<string>? Files { get; set; }
        public bool IsSubmitted { get; set; }
    }
}
