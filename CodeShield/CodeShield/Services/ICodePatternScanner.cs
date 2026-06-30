using System.Collections.Generic;
using System.Threading.Tasks;
using CodeShield.Models;

namespace CodeShield.Services
{
    public interface ICodePatternScanner
    {
        Task<List<CodeIssue>> ScanAsync(string repositoryUrl, List<string> files, List<Ecosystem> detectedEcosystems);
    }
}
