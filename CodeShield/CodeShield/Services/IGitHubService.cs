using System.Collections.Generic;
using System.Threading.Tasks;
using CodeShield.Models;

namespace CodeShield.Services
{
    public interface IGitHubService
    {
        Task<(List<string>? Files, List<DependencyPackage>? Packages, List<Ecosystem>? DetectedEcosystems, string? ErrorMessage)> GetRepositoryFilesAsync(string repositoryUrl);
        Task<string?> GetFileContentAsync(string repositoryUrl, string path);
    }
}
