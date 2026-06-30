using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CodeShield.Models;

namespace CodeShield.Services
{
    public class CodePatternScanner : ICodePatternScanner
    {
        private readonly IGitHubService _gitHubService;

        // Compiled Regexes
        private static readonly Regex HardcodedSecretRegex = new Regex(
            @"(?i)\b[a-z0-9_]*(password|apikey|api_key|secret|token)[a-z0-9_]*\s*=\s*@?(['""])(?<val>.+?)\2",
            RegexOptions.Compiled);

        private static readonly Regex SqlConcatenationRegex1 = new Regex(
            @"(?i)([""'])(.*?)\b(select|insert|update|delete)\b(.*?)\1\s*\+\s*[a-zA-Z_]",
            RegexOptions.Compiled);

        private static readonly Regex SqlConcatenationRegex2 = new Regex(
            @"(?i)[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*([""'])(.*?)\b(select|insert|update|delete)\b(.*?)\1",
            RegexOptions.Compiled);

        private static readonly Regex SqlInterpolationRegex = new Regex(
            @"(?i)(?:\$|f)?([""'])((?:(?!\1).)*)\b(select|insert|update|delete)\b((?:(?!\1).)*?)(?:\{[a-zA-Z_][a-zA-Z0-9_]*\}|\$\{[a-zA-Z_][a-zA-Z0-9_]*\})((?:(?!\1).)*)\1",
            RegexOptions.Compiled);

        private static readonly Regex ConnectionStringRegex = new Regex(
            @"(?i)([""'])([^""'\r\n]*(?:Server=|Data Source=|datasource=)[^""'\r\n]*)\1",
            RegexOptions.Compiled);

        private static readonly Regex ApiKeyLikeRegex = new Regex(
            @"([""'])(?<val>[a-zA-Z0-9_\-]{24,60})\1",
            RegexOptions.Compiled);

        private static readonly Regex InsecureHttpRegex = new Regex(
            @"(?i)([""'])(?<url>http://[^""'\r\n\s>]+)\1",
            RegexOptions.Compiled);

        public CodePatternScanner(IGitHubService gitHubService)
        {
            _gitHubService = gitHubService;
        }

        public async Task<List<CodeIssue>> ScanAsync(string repositoryUrl, List<string> files, List<Ecosystem> detectedEcosystems)
        {
            var issues = new List<CodeIssue>();

            if (files == null || files.Count == 0 || detectedEcosystems == null || detectedEcosystems.Count == 0)
            {
                return issues;
            }

            var swFilter = System.Diagnostics.Stopwatch.StartNew();

            // Determine target extensions
            var targetExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (detectedEcosystems.Contains(Ecosystem.NuGet))
            {
                targetExtensions.Add(".cs");
            }
            if (detectedEcosystems.Contains(Ecosystem.Npm))
            {
                targetExtensions.Add(".js");
            }
            if (detectedEcosystems.Contains(Ecosystem.Python))
            {
                targetExtensions.Add(".py");
            }

            if (targetExtensions.Count == 0)
            {
                swFilter.Stop();
                return issues;
            }

            // Filter relevant files
            var filteredFiles = files
                .Where(f =>
                {
                    string ext = Path.GetExtension(f);
                    if (!targetExtensions.Contains(ext))
                    {
                        return false;
                    }

                    string lowerPath = f.ToLowerInvariant();
                    // Skip third-party, configuration, build output, tests, etc.
                    if (lowerPath.Contains("node_modules/") ||
                        lowerPath.Contains("vendor/") ||
                        lowerPath.Contains("dist/") ||
                        lowerPath.Contains("bin/") ||
                        lowerPath.Contains("obj/") ||
                        lowerPath.Contains("test/") ||
                        lowerPath.Contains("tests/") ||
                        lowerPath.Contains(".git/") ||
                        lowerPath.Contains(".github/") ||
                        lowerPath.Contains(".vs/") ||
                        lowerPath.Contains("test") ||
                        lowerPath.Contains("spec") ||
                        lowerPath.EndsWith(".min.js"))
                    {
                        return false;
                    }

                    return true;
                })
                .Take(25) // Enforce a safety threshold limit to avoid excessive API requests
                .ToList();

            swFilter.Stop();
            Console.WriteLine($"[TIMING] Phase 2: Filtering files took {swFilter.ElapsedMilliseconds} ms. Total files found: {files.Count}. Files to scan (after filter & cap): {filteredFiles.Count}.");

            var swFetch = System.Diagnostics.Stopwatch.StartNew();

            // Fetch file contents in parallel (max 10 concurrent requests)
            var fetchResults = new List<(string File, string? Content)>();
            using (var semaphore = new System.Threading.SemaphoreSlim(10))
            {
                var fetchTasks = filteredFiles.Select(async file =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        string? content = await _gitHubService.GetFileContentAsync(repositoryUrl, file);
                        return (File: file, Content: content);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                });
                fetchResults = (await Task.WhenAll(fetchTasks)).ToList();
            }

            swFetch.Stop();
            Console.WriteLine($"[TIMING] Phase 3: Fetching file contents took {swFetch.ElapsedMilliseconds} ms for {filteredFiles.Count} files.");

            var swRegex = System.Diagnostics.Stopwatch.StartNew();

            foreach (var result in fetchResults)
            {
                string file = result.File;
                string? fileContent = result.Content;
                if (string.IsNullOrEmpty(fileContent))
                {
                    continue;
                }

                var lines = fileContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];
                    string trimmed = line.Trim();
                    int lineNumber = i + 1;

                    // 1. HardcodedSecret check
                    var secretMatch = HardcodedSecretRegex.Match(line);
                    if (secretMatch.Success)
                    {
                        string secretVal = secretMatch.Groups["val"].Value;
                        if (secretVal.Length >= 8)
                        {
                            issues.Add(new CodeIssue
                            {
                                FileName = file,
                                LineNumber = lineNumber,
                                IssueType = IssueType.HardcodedSecret,
                                CodeSnippet = trimmed,
                                Severity = Severity.High
                            });
                            continue; // Avoid duplicate alerts on the same line if possible
                        }
                    }

                    // 2. SqlInjectionRisk check
                    if (SqlInterpolationRegex.IsMatch(line) ||
                        SqlConcatenationRegex1.IsMatch(line) ||
                        SqlConcatenationRegex2.IsMatch(line))
                    {
                        issues.Add(new CodeIssue
                        {
                            FileName = file,
                            LineNumber = lineNumber,
                            IssueType = IssueType.SqlInjectionRisk,
                            CodeSnippet = trimmed,
                            Severity = Severity.Critical
                        });
                        continue;
                    }

                    // 3. ExposedConfig check
                    var connMatch = ConnectionStringRegex.Match(line);
                    if (connMatch.Success)
                    {
                        issues.Add(new CodeIssue
                        {
                            FileName = file,
                            LineNumber = lineNumber,
                            IssueType = IssueType.ExposedConfig,
                            CodeSnippet = trimmed,
                            Severity = Severity.High
                        });
                        continue;
                    }

                    var apiKeyMatch = ApiKeyLikeRegex.Match(line);
                    if (apiKeyMatch.Success)
                    {
                        string val = apiKeyMatch.Groups["val"].Value;
                        // Key-like strings must contain both letters and digits to avoid false positives
                        if (val.Any(char.IsLetter) && val.Any(char.IsDigit))
                        {
                            issues.Add(new CodeIssue
                            {
                                FileName = file,
                                LineNumber = lineNumber,
                                IssueType = IssueType.ExposedConfig,
                                CodeSnippet = trimmed,
                                Severity = Severity.High
                            });
                            continue;
                        }
                    }

                    // 4. InsecureHttp check
                    var httpMatches = InsecureHttpRegex.Matches(line);
                    bool hasInsecureHttp = false;
                    foreach (Match httpMatch in httpMatches)
                    {
                        string url = httpMatch.Groups["url"].Value;
                        if (!IsExcludedHttpUrl(url))
                        {
                            hasInsecureHttp = true;
                            break;
                        }
                    }

                    if (hasInsecureHttp)
                    {
                        issues.Add(new CodeIssue
                        {
                            FileName = file,
                            LineNumber = lineNumber,
                            IssueType = IssueType.InsecureHttp,
                            CodeSnippet = trimmed,
                            Severity = Severity.Low
                        });
                    }
                }
            }

            swRegex.Stop();
            Console.WriteLine($"[TIMING] Phase 4: Regex pattern matching took {swRegex.ElapsedMilliseconds} ms.");

            return issues;
        }

        private bool IsExcludedHttpUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return true;
            }

            string lower = url.ToLowerInvariant();
            return lower.StartsWith("http://localhost") ||
                   lower.StartsWith("http://127.0.0.1") ||
                   lower.Contains("w3.org") ||
                   lower.Contains("schemas.") ||
                   lower.Contains("tempuri.org");
        }
    }
}
