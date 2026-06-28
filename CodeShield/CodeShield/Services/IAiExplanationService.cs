using System.Threading.Tasks;

namespace CodeShield.Services
{
    public interface IAiExplanationService
    {
        Task<(string? Explanation, string? Fix)> ExplainVulnerabilityAsync(string packageName, string version, string vulnId, string description);
    }
}
