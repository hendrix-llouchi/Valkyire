using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using CodeShield.Models;
using CodeShield.Services;

namespace CodeShield.Controllers
{
    [Authorize]
    public class ScanController : Controller
    {
        private readonly IGitHubService _gitHubService;
        private readonly IOsvService _osvService;
        private readonly IAiExplanationService _aiExplanationService;

        public ScanController(IGitHubService gitHubService, IOsvService osvService, IAiExplanationService aiExplanationService)
        {
            _gitHubService = gitHubService;
            _osvService = osvService;
            _aiExplanationService = aiExplanationService;
        }

        [HttpGet]
        [Route("Scan")]
        public IActionResult Index()
        {
            return View(new ScanViewModel());
        }


        [HttpPost]
        [Route("Scan")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ScanViewModel model)
        {
            model.IsSubmitted = true;

            if (string.IsNullOrWhiteSpace(model.RepositoryUrl))
            {
                model.ErrorMessage = "Please enter a valid GitHub repository URL.";
                return View(model);
            }

            var (files, packages, detectedEcosystems, errorMessage) = await _gitHubService.GetRepositoryFilesAsync(model.RepositoryUrl);

            if (errorMessage != null)
            {
                model.ErrorMessage = errorMessage;
            }
            else
            {
                model.Files = files;
                model.Packages = packages;
                model.DetectedEcosystems = detectedEcosystems;

                if (packages != null && packages.Count > 0)
                {
                    var (osvSuccess, osvErrorMessage) = await _osvService.CheckVulnerabilitiesAsync(packages);
                    if (!osvSuccess || osvErrorMessage != null)
                    {
                        model.OsvWarningMessage = osvErrorMessage ?? "Some packages could not be checked due to a temporary issue — try rescanning for complete results.";
                    }

                    // Concurrent AI explanation queries (limit 5) for NuGet and npm package vulnerabilities
                    var nonPythonPackages = packages.Where(p => p.Ecosystem != Ecosystem.Python).ToList();
                    var vulnerabilitiesToExplain = nonPythonPackages
                        .SelectMany(p => p.Vulnerabilities.Select(v => new { Package = p, Vulnerability = v }))
                        .ToList();

                    if (vulnerabilitiesToExplain.Count > 0)
                    {
                        using var semaphore = new SemaphoreSlim(5);
                        var tasks = vulnerabilitiesToExplain.Select(async item =>
                        {
                            await semaphore.WaitAsync();
                            try
                            {
                                var (explanation, fix) = await _aiExplanationService.ExplainVulnerabilityAsync(
                                    item.Package.PackageName,
                                    item.Package.Version,
                                    item.Vulnerability.Id,
                                    item.Vulnerability.Description
                                );

                                item.Vulnerability.AiExplanation = explanation;
                                item.Vulnerability.AiFixSuggestion = fix;
                            }
                            finally
                            {
                                semaphore.Release();
                            }
                        });
                        await Task.WhenAll(tasks);
                    }
                }
            }

            return View(model);
        }
    }
}
