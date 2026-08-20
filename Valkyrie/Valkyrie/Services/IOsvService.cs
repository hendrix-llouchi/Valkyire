using System.Collections.Generic;
using System.Threading.Tasks;
using Valkyrie.Models;

namespace Valkyrie.Services
{
    public interface IOsvService
    {
        Task<(bool Success, string? ErrorMessage)> CheckVulnerabilitiesAsync(List<DependencyPackage> packages);
    }
}
