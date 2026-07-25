using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using CodeShield.Models;
using CodeShield.Services;
using CodeShield.Data;

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
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;

        public ScanController(
            IGitHubService gitHubService, 
            IOsvService osvService, 
            IAiExplanationService aiExplanationService,
            ICodePatternScanner codePatternScanner,
            IConfiguration configuration,
            ApplicationDbContext context,
            UserManager<IdentityUser> userManager)
        {
            _gitHubService = gitHubService;
            _osvService = osvService;
            _aiExplanationService = aiExplanationService;
            _codePatternScanner = codePatternScanner;
            _configuration = configuration;
            _context = context;
            _userManager = userManager;
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
        public async Task<IActionResult> Index(string? repositoryUrl = null)
        {
            if (!string.IsNullOrWhiteSpace(repositoryUrl))
            {
                var model = new ScanViewModel { RepositoryUrl = repositoryUrl };
                return await Index(model);
            }
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

                foreach (var aiTask in tasksToExecute)
                {
                    await aiTask.ExecuteAiExplanationAsync();
                }

                swAi.Stop();
                Console.WriteLine($"[TIMING] Phase 5: Combined AI explanations took {swAi.ElapsedMilliseconds} ms for {tasksToExecute.Count} tasks.");

                // Save scan results to the database since the scan completed successfully
                var userId = _userManager.GetUserId(User);
                if (!string.IsNullOrEmpty(userId))
                {
                    var vulnList = packages?.Where(p => p.Ecosystem != Ecosystem.Python)
                                           .SelectMany(p => p.Vulnerabilities)
                                           .ToList() ?? new List<VulnerabilityDetail>();
                    var codeIssueList = model.CodeIssues ?? new List<CodeIssue>();

                    int criticalCount = vulnList.Count(v => v.Severity == Severity.Critical) + codeIssueList.Count(c => c.Severity == Severity.Critical);
                    int highCount = vulnList.Count(v => v.Severity == Severity.High) + codeIssueList.Count(c => c.Severity == Severity.High);
                    int mediumCount = vulnList.Count(v => v.Severity == Severity.Medium) + codeIssueList.Count(c => c.Severity == Severity.Medium);
                    int lowCount = vulnList.Count(v => v.Severity == Severity.Low) + codeIssueList.Count(c => c.Severity == Severity.Low);

                    string grade = ComputeSecurityGrade(criticalCount, highCount, mediumCount, lowCount);
                    string ecosystemsDetected = model.DetectedEcosystems != null ? string.Join(", ", model.DetectedEcosystems) : "";
                    var status = string.IsNullOrEmpty(model.OsvWarningMessage) ? ScanStatus.Completed : ScanStatus.PartialFailure;
                    int totalIssuesFound = vulnList.Count + codeIssueList.Count;

                    var scanResult = new ScanResult
                    {
                        UserId = userId,
                        RepositoryUrl = model.RepositoryUrl,
                        RepositoryName = ExtractRepositoryName(model.RepositoryUrl),
                        EcosystemsDetected = ecosystemsDetected,
                        SecurityGrade = grade,
                        TotalIssuesFound = totalIssuesFound,
                        ScannedAt = DateTime.UtcNow,
                        Status = status
                    };

                    if (packages != null)
                    {
                        foreach (var pkg in packages)
                        {
                            if (pkg.Vulnerabilities != null && pkg.Vulnerabilities.Count > 0)
                            {
                                foreach (var vuln in pkg.Vulnerabilities)
                                {
                                    scanResult.VulnerablePackages.Add(new VulnerablePackage
                                    {
                                        PackageName = pkg.PackageName,
                                        Ecosystem = pkg.Ecosystem,
                                        InstalledVersion = pkg.Version,
                                        SafeVersion = null,
                                        Severity = vuln.Severity,
                                        Description = vuln.Description,
                                        AiExplanation = vuln.AiExplanation,
                                        AiFixSuggestion = vuln.AiFixSuggestion
                                    });
                                }
                            }
                        }
                    }

                    if (model.CodeIssues != null)
                    {
                        foreach (var issue in model.CodeIssues)
                        {
                            scanResult.CodeIssues.Add(new CodeIssue
                            {
                                FileName = issue.FileName,
                                LineNumber = issue.LineNumber,
                                IssueType = issue.IssueType,
                                CodeSnippet = issue.CodeSnippet,
                                Severity = issue.Severity,
                                AiExplanation = issue.AiExplanation,
                                AiFixSuggestion = issue.AiFixSuggestion
                            });
                        }
                    }

                    _context.ScanResults.Add(scanResult);
                    await _context.SaveChangesAsync();
                }
            }

            swTotal.Stop();
            Console.WriteLine($"[TIMING] Phase 7: Total action execution took {swTotal.ElapsedMilliseconds} ms.");
            return View(model);
        }

        private string ExtractRepositoryName(string url)
        {
            try
            {
                var regex = new System.Text.RegularExpressions.Regex(@"^https?://(www\.)?github\.com/(?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?/?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                var match = regex.Match(url.Trim());
                if (match.Success)
                {
                    return match.Groups["repo"].Value;
                }
            }
            catch { }
            return "Unknown Repository";
        }

        private string ComputeSecurityGrade(int criticalCount, int highCount, int mediumCount, int lowCount)
        {
            int totalIssues = criticalCount + highCount + mediumCount + lowCount;
            if (totalIssues == 0)
            {
                return "A";
            }

            int score = 100 - (criticalCount * 20 + highCount * 10 + mediumCount * 5 + lowCount * 2);

            if (score >= 90)
            {
                return "A";
            }
            if (score >= 75)
            {
                return "B";
            }
            if (score >= 60)
            {
                return "C";
            }
            if (score >= 45)
            {
                return "D";
            }
            return "F";
        }

        [HttpGet]
        [Route("Scans")]
        public async Task<IActionResult> History()
        {
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(userId))
            {
                return Challenge();
            }

            var scans = await _context.ScanResults
                .Where(s => s.UserId == userId)
                .OrderByDescending(s => s.ScannedAt)
                .ToListAsync();

            return View("History", scans);
        }

        [HttpGet]
        [Route("Scans/{id:int}")]
        public async Task<IActionResult> Details(int id)
        {
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(userId))
            {
                return Challenge();
            }

            var scan = await _context.ScanResults
                .Include(s => s.VulnerablePackages)
                .Include(s => s.CodeIssues)
                .FirstOrDefaultAsync(s => s.Id == id && s.UserId == userId);

            if (scan == null)
            {
                return NotFound();
            }

            return View("Details", scan);
        }

        [HttpPost]
        [Route("Scans/Delete/{id:int}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(int id, string? returnUrl = null)
        {
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(userId))
            {
                return Challenge();
            }

            var scan = await _context.ScanResults.FirstOrDefaultAsync(s => s.Id == id && s.UserId == userId);
            if (scan != null)
            {
                _context.ScanResults.Remove(scan);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Scan history record deleted successfully.";
            }

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("History");
        }

        [HttpPost]
        [Route("Scans/DeleteAll")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAll(string? returnUrl = null)
        {
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(userId))
            {
                return Challenge();
            }

            var userScans = await _context.ScanResults.Where(s => s.UserId == userId).ToListAsync();
            if (userScans.Any())
            {
                _context.ScanResults.RemoveRange(userScans);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "All scan history cleared successfully.";
            }

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("History");
        }
    }
}
