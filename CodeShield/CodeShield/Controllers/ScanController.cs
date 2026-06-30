using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
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
        private readonly ICodePatternScanner _codePatternScanner;
        private readonly IConfiguration _configuration;

        public ScanController(
            IGitHubService gitHubService, 
            IOsvService osvService, 
            IAiExplanationService aiExplanationService,
            ICodePatternScanner codePatternScanner,
            IConfiguration configuration)
        {
            _gitHubService = gitHubService;
            _osvService = osvService;
            _aiExplanationService = aiExplanationService;
            _codePatternScanner = codePatternScanner;
            _configuration = configuration;
        }

        private class AiTaskWrapper
        {
            public Severity Severity { get; set; }
            public string TypeName { get; set; } = null!;
            public string IssueKey { get; set; } = null!;
            public Func<Task> ExecuteAiExplanationAsync { get; set; } = null!;
            public Action<string, string> SetResult { get; set; } = null!;
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
            var swTotal = System.Diagnostics.Stopwatch.StartNew();
            model.IsSubmitted = true;

            if (string.IsNullOrWhiteSpace(model.RepositoryUrl))
            {
                model.ErrorMessage = "Please enter a valid GitHub repository URL.";
                return View(model);
            }

            var swFileTree = System.Diagnostics.Stopwatch.StartNew();
            var (files, packages, detectedEcosystems, errorMessage) = await _gitHubService.GetRepositoryFilesAsync(model.RepositoryUrl);
            swFileTree.Stop();
            Console.WriteLine($"[TIMING] Phase 1: Fetching file tree took {swFileTree.ElapsedMilliseconds} ms.");

            if (errorMessage != null)
            {
                model.ErrorMessage = errorMessage;
            }
            else
            {
                model.Files = files;
                model.Packages = packages;
                model.DetectedEcosystems = detectedEcosystems;

                // 1. Run package vulnerabilities check (Phase 6)
                var swOsv = System.Diagnostics.Stopwatch.StartNew();
                int vulnCount = 0;
                if (packages != null && packages.Count > 0)
                {
                    var (osvSuccess, osvErrorMessage) = await _osvService.CheckVulnerabilitiesAsync(packages);
                    if (!osvSuccess || osvErrorMessage != null)
                    {
                        model.OsvWarningMessage = osvErrorMessage ?? "Some packages could not be checked due to a temporary issue — try rescanning for complete results.";
                    }
                    vulnCount = packages.Sum(p => p.Vulnerabilities.Count);
                }
                swOsv.Stop();
                Console.WriteLine($"[TIMING] Phase 6: OSV.dev check took {swOsv.ElapsedMilliseconds} ms. Found {vulnCount} vulnerabilities across {packages?.Count ?? 0} packages.");

                // 2. Run code pattern scanning
                if (files != null && files.Count > 0 && detectedEcosystems != null && detectedEcosystems.Count > 0)
                {
                    var codeIssues = await _codePatternScanner.ScanAsync(model.RepositoryUrl, files, detectedEcosystems);
                    model.CodeIssues = codeIssues;
                }

                // 3. Combined concurrent/paced AI explanations
                var swAi = System.Diagnostics.Stopwatch.StartNew();
                var allAiTasks = new List<AiTaskWrapper>();

                // Add vulnerability AI tasks
                if (packages != null && packages.Count > 0)
                {
                    var nonPythonPackages = packages.Where(p => p.Ecosystem != Ecosystem.Python).ToList();
                    var vulnerabilitiesToExplain = nonPythonPackages
                        .SelectMany(p => p.Vulnerabilities.Select(v => new { Package = p, Vulnerability = v }))
                        .ToList();

                    foreach (var item in vulnerabilitiesToExplain)
                    {
                        var targetItem = item;
                        allAiTasks.Add(new AiTaskWrapper
                        {
                            Severity = targetItem.Vulnerability.Severity,
                            TypeName = "Vulnerability",
                            IssueKey = targetItem.Vulnerability.Id,
                            ExecuteAiExplanationAsync = async () =>
                            {
                                var (explanation, fix) = await _aiExplanationService.ExplainVulnerabilityAsync(
                                    targetItem.Package.PackageName,
                                    targetItem.Package.Version,
                                    targetItem.Vulnerability.Id,
                                    targetItem.Vulnerability.Description
                                );
                                targetItem.Vulnerability.AiExplanation = explanation;
                                targetItem.Vulnerability.AiFixSuggestion = fix;
                            },
                            SetResult = (exp, fix) =>
                            {
                                targetItem.Vulnerability.AiExplanation = exp;
                                targetItem.Vulnerability.AiFixSuggestion = fix;
                            }
                        });
                    }
                }

                // Add code issue AI tasks
                if (model.CodeIssues != null && model.CodeIssues.Count > 0)
                {
                    foreach (var issue in model.CodeIssues)
                    {
                        var targetIssue = issue;
                        allAiTasks.Add(new AiTaskWrapper
                        {
                            Severity = targetIssue.Severity,
                            TypeName = "CodeIssue",
                            IssueKey = targetIssue.IssueType.ToString(),
                            ExecuteAiExplanationAsync = async () =>
                            {
                                var (explanation, fix) = await _aiExplanationService.ExplainCodeIssueAsync(
                                    targetIssue.FileName,
                                    targetIssue.LineNumber,
                                    targetIssue.IssueType.ToString(),
                                    targetIssue.CodeSnippet ?? string.Empty
                                );
                                targetIssue.AiExplanation = explanation;
                                targetIssue.AiFixSuggestion = fix;
                            },
                            SetResult = (exp, fix) =>
                            {
                                targetIssue.AiExplanation = exp;
                                targetIssue.AiFixSuggestion = fix;
                            }
                        });
                    }
                }

                int maxExplanations = _configuration.GetValue<int>("AiExplanation:MaxExplanations", 30);
                bool enableCap = _configuration.GetValue<bool>("AiExplanation:EnableCap", false);

                List<AiTaskWrapper> tasksToExecute;
                List<AiTaskWrapper> tasksToSkip;

                var sortedTasks = allAiTasks.OrderBy(t => (int)t.Severity).ToList();

                if (enableCap && sortedTasks.Count > maxExplanations)
                {
                    tasksToExecute = sortedTasks.Take(maxExplanations).ToList();
                    tasksToSkip = sortedTasks.Skip(maxExplanations).ToList();
                }
                else
                {
                    tasksToExecute = sortedTasks;
                    tasksToSkip = new List<AiTaskWrapper>();
                }

                // Group skipped tasks by issue key/type to format the skip message
                var skippedCounts = tasksToSkip
                    .GroupBy(t => t.IssueKey)
                    .ToDictionary(g => g.Key, g => g.Count());

                foreach (var task in tasksToSkip)
                {
                    int count = skippedCounts[task.IssueKey];
                    string countText = count == 1 ? "1 other issue" : $"{count} other issues";
                    string verbText = count == 1 ? "was" : "were";
                    string explanation = $"AI explanation skipped to keep scan time reasonable - {countText} with this same risk type {verbText} found.";
                    string fix = task.TypeName == "Vulnerability"
                        ? "Upgrade the package to a safe version."
                        : "Review the code snippet and remediate the insecure pattern manually.";
                    task.SetResult(explanation, fix);
                }

                var aiTasks = tasksToExecute.Select(t => t.ExecuteAiExplanationAsync()).ToList();
                if (aiTasks.Count > 0)
                {
                    await Task.WhenAll(aiTasks);
                }

                swAi.Stop();
                Console.WriteLine($"[TIMING] Phase 5: Combined AI explanations took {swAi.ElapsedMilliseconds} ms for {aiTasks.Count} tasks.");
            }

            swTotal.Stop();
            Console.WriteLine($"[TIMING] Phase 7: Total action execution took {swTotal.ElapsedMilliseconds} ms.");
            return View(model);
        }
    }
}
