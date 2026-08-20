using System.Collections.Generic;
using System.Threading.Tasks;
using Valkyrie.Models;

namespace Valkyrie.Services
{
    public interface ICodePatternScanner
    {
        Task<List<CodeIssue>> ScanAsync(string repositoryUrl, List<string> files, List<Ecosystem> detectedEcosystems);
    }
}
