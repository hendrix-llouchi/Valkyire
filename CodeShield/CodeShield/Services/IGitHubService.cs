using System.Collections.Generic;
using System.Threading.Tasks;

namespace CodeShield.Services
{
    public interface IGitHubService
    {
        Task<(List<string>? Files, string? ErrorMessage)> GetRepositoryFilesAsync(string repositoryUrl);
    }
}
