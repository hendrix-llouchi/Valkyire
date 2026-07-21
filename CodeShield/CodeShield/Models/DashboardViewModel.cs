using System.Collections.Generic;

namespace CodeShield.Models
{
    public class DashboardViewModel
    {
        public int TotalScanned { get; set; }
        public int TotalIssues { get; set; }
        public string OverallGrade { get; set; } = "N/A";
        public List<ScanResult> RecentScans { get; set; } = new List<ScanResult>();
    }
}
