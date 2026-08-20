using System.Collections.Generic;

namespace Valkyrie.Models
{
    public class DependencyPackage
    {
        public string PackageName { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public Ecosystem Ecosystem { get; set; }
        public List<VulnerabilityDetail> Vulnerabilities { get; set; } = new List<VulnerabilityDetail>();
    }
}
