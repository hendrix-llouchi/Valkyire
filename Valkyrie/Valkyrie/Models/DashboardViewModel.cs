using System.Collections.Generic;

namespace Valkyrie.Models
{
    public class DashboardViewModel
    {
        public int TotalScanned { get; set; }
        public int TotalIssues { get; set; }
        public string OverallGrade { get; set; } = "N/A";
        public List<ScanResult> RecentScans { get; set; } = new List<ScanResult>();
    }
}
