using System.Threading.Tasks;

namespace Valkyrie.Services
{
    public interface IAiExplanationService
    {
        Task<(string? Explanation, string? Fix)> ExplainVulnerabilityAsync(string packageName, string version, string vulnId, string description);
        Task<(string? Explanation, string? Fix)> ExplainCodeIssueAsync(string fileName, int lineNumber, string issueType, string codeSnippet);
    }
}
