using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using CodeShield.Models;

namespace CodeShield.Services
{
    public class GitHubService : IGitHubService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;

        public GitHubService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;

            // Configure HttpClient defaults
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("CodeShield-App");
            _httpClient.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github.v3+json");

            var token = _configuration["GitHub:Token"];
            if (!string.IsNullOrEmpty(token))
            {
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            }
        }

        public async Task<(List<string>? Files, List<DependencyPackage>? Packages, List<Ecosystem>? DetectedEcosystems, string? ErrorMessage)> GetRepositoryFilesAsync(string repositoryUrl)
        {
            if (string.IsNullOrWhiteSpace(repositoryUrl))
            {
                return (null, null, null, "Please enter a valid GitHub repository URL.");
            }

            // Validate and parse GitHub URL
            var regex = new Regex(@"^https?://(www\.)?github\.com/(?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?/?$", RegexOptions.IgnoreCase);
            var match = regex.Match(repositoryUrl.Trim());

            if (!match.Success)
            {
                return (null, null, null, "Please enter a valid GitHub repository URL.");
            }

            string owner = match.Groups["owner"].Value;
            string repo = match.Groups["repo"].Value;

            // 1. Get repository details to verify existence, public status, and default branch
            string repoUrl = $"https://api.github.com/repos/{owner}/{repo}";
            var (repoResponse, repoError) = await SendWithRateLimitCheckAsync(repoUrl);

            if (repoError != null)
            {
                return (null, null, null, repoError);
            }

            if (repoResponse == null)
            {
                return (null, null, null, "This repository could not be accessed. Make sure it's public and the URL is correct.");
            }

            string defaultBranch = "main";
            try
            {
                var repoJson = await repoResponse.Content.ReadAsStringAsync();
                using var repoDoc = JsonDocument.Parse(repoJson);
                if (repoDoc.RootElement.TryGetProperty("default_branch", out var defaultBranchProp))
                {
                    defaultBranch = defaultBranchProp.GetString() ?? "main";
                }
            }
            catch (Exception)
            {
                return (null, null, null, "Failed to parse repository information from GitHub API.");
            }

            // 2. Fetch the recursive git tree for the default branch
            string treeUrl = $"https://api.github.com/repos/{owner}/{repo}/git/trees/{defaultBranch}?recursive=1";
            var (treeResponse, treeError) = await SendWithRateLimitCheckAsync(treeUrl);

            if (treeError != null)
            {
                return (null, null, null, treeError);
            }

            if (treeResponse == null)
            {
                return (null, null, null, "Failed to retrieve the file list from GitHub.");
            }

            try
            {
                var treeJson = await treeResponse.Content.ReadAsStringAsync();
                using var treeDoc = JsonDocument.Parse(treeJson);
                if (!treeDoc.RootElement.TryGetProperty("tree", out var treeElement))
                {
                    return (null, null, null, "Failed to parse file tree. The repository might be empty.");
                }

                var files = new List<string>();
                foreach (var item in treeElement.EnumerateArray())
                {
                    if (item.TryGetProperty("type", out var typeProp) && typeProp.GetString() == "blob")
                    {
                        if (item.TryGetProperty("path", out var pathProp))
                        {
                            files.Add(pathProp.GetString() ?? "");
                        }
                    }
                }

                // Check file count threshold
                if (files.Count > 1000)
                {
                    return (null, null, null, "This repository is too large to scan in full. CodeShield currently supports repositories up to 1000 files.");
                }

                // Scan for supported dependency files
                var detectedDependencyFiles = new List<string>();
                foreach (var f in files)
                {
                    string fileName = System.IO.Path.GetFileName(f).ToLowerInvariant();
                    if (fileName == "package.json" || fileName.EndsWith(".csproj") || fileName == "requirements.txt")
                    {
                        detectedDependencyFiles.Add(f);
                    }
                }

                if (detectedDependencyFiles.Count == 0)
                {
                    return (null, null, null, "No supported dependency files found. CodeShield supports npm (package.json), NuGet (*.csproj), and Python (requirements.txt).");
                }

                // Fetch and parse each detected dependency file
                var packages = new List<DependencyPackage>();
                var successfullyReadEcosystems = new HashSet<Ecosystem>();

                foreach (var path in detectedDependencyFiles)
                {
                    try
                    {
                        string contentUrl = $"https://api.github.com/repos/{owner}/{repo}/contents/{Uri.EscapeDataString(path)}";
                        var (contentResponse, contentError) = await SendWithRateLimitCheckAsync(contentUrl);
                        if (contentError != null || contentResponse == null)
                        {
                            continue;
                        }

                        var contentJson = await contentResponse.Content.ReadAsStringAsync();
                        using var contentDoc = JsonDocument.Parse(contentJson);
                        if (contentDoc.RootElement.TryGetProperty("content", out var contentProp))
                        {
                            var base64Content = contentProp.GetString() ?? string.Empty;
                            base64Content = base64Content.Replace("\n", "").Replace("\r", "").Trim();
                            var fileBytes = Convert.FromBase64String(base64Content);
                            var fileContent = Encoding.UTF8.GetString(fileBytes).TrimStart('\uFEFF');

                            string fileName = System.IO.Path.GetFileName(path).ToLowerInvariant();
                            if (fileName == "package.json")
                            {
                                ParsePackageJson(fileContent, packages);
                                successfullyReadEcosystems.Add(Ecosystem.Npm);
                            }
                            else if (fileName.EndsWith(".csproj"))
                            {
                                ParseCsproj(fileContent, packages);
                                successfullyReadEcosystems.Add(Ecosystem.NuGet);
                            }
                            else if (fileName == "requirements.txt")
                            {
                                ParseRequirementsTxt(fileContent, packages);
                                successfullyReadEcosystems.Add(Ecosystem.Python);
                            }
                        }
                    }
                    catch
                    {
                        // Ignore file-specific fetching or parsing errors to continue scanning other files
                    }
                }

                return (files, packages, successfullyReadEcosystems.ToList(), null);
            }
            catch (Exception)
            {
                return (null, null, null, "An error occurred while parsing the repository files.");
            }
        }

        private void ParsePackageJson(string content, List<DependencyPackage> packages)
        {
            try
            {
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;

                if (root.TryGetProperty("dependencies", out var depsElement) && depsElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in depsElement.EnumerateObject())
                    {
                        packages.Add(new DependencyPackage
                        {
                            PackageName = prop.Name,
                            Version = prop.Value.ValueKind == JsonValueKind.String ? (prop.Value.GetString() ?? string.Empty) : prop.Value.ToString(),
                            Ecosystem = Ecosystem.Npm
                        });
                    }
                }

                if (root.TryGetProperty("devDependencies", out var devDepsElement) && devDepsElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in devDepsElement.EnumerateObject())
                    {
                        packages.Add(new DependencyPackage
                        {
                            PackageName = prop.Name,
                            Version = prop.Value.ValueKind == JsonValueKind.String ? (prop.Value.GetString() ?? string.Empty) : prop.Value.ToString(),
                            Ecosystem = Ecosystem.Npm
                        });
                    }
                }
            }
            catch
            {
                // Ignore malformed package.json
            }
        }

        private void ParseCsproj(string content, List<DependencyPackage> packages)
        {
            try
            {
                var doc = XDocument.Parse(content);
                var packageReferences = doc.Descendants().Where(x => x.Name.LocalName.Equals("PackageReference", StringComparison.OrdinalIgnoreCase));

                foreach (var pr in packageReferences)
                {
                    var includeAttr = pr.Attributes().FirstOrDefault(x => x.Name.LocalName.Equals("Include", StringComparison.OrdinalIgnoreCase) || x.Name.LocalName.Equals("Update", StringComparison.OrdinalIgnoreCase));
                    var versionAttr = pr.Attributes().FirstOrDefault(x => x.Name.LocalName.Equals("Version", StringComparison.OrdinalIgnoreCase));

                    if (includeAttr != null)
                    {
                        string packageName = includeAttr.Value;
                        string version = versionAttr?.Value ?? string.Empty;

                        if (string.IsNullOrEmpty(version))
                        {
                            var versionEl = pr.Elements().FirstOrDefault(x => x.Name.LocalName.Equals("Version", StringComparison.OrdinalIgnoreCase));
                            if (versionEl != null)
                            {
                                version = versionEl.Value;
                            }
                        }

                        packages.Add(new DependencyPackage
                        {
                            PackageName = packageName,
                            Version = version,
                            Ecosystem = Ecosystem.NuGet
                        });
                    }
                }
            }
            catch
            {
                // Ignore malformed .csproj
            }
        }

        private void ParseRequirementsTxt(string content, List<DependencyPackage> packages)
        {
            try
            {
                var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                var operators = new[] { "==", ">=", "~=" };

                foreach (var rawLine in lines)
                {
                    var line = rawLine.Trim();
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    {
                        continue;
                    }

                    string? foundOperator = null;
                    int operatorIndex = -1;

                    foreach (var op in operators)
                    {
                        int idx = line.IndexOf(op);
                        if (idx != -1 && (operatorIndex == -1 || idx < operatorIndex))
                        {
                            operatorIndex = idx;
                            foundOperator = op;
                        }
                    }

                    if (operatorIndex != -1 && foundOperator != null)
                    {
                        string name = line.Substring(0, operatorIndex).Trim();
                        string versionPart = line.Substring(operatorIndex + foundOperator.Length).Trim();

                        int spaceIdx = versionPart.IndexOfAny(new[] { ' ', ';', '#' });
                        string version = spaceIdx != -1 ? versionPart.Substring(0, spaceIdx).Trim() : versionPart;

                        packages.Add(new DependencyPackage
                        {
                            PackageName = name,
                            Version = version,
                            Ecosystem = Ecosystem.Python
                        });
                    }
                }
            }
            catch
            {
                // Ignore malformed requirements.txt
            }
        }

        public async Task<string?> GetFileContentAsync(string repositoryUrl, string path)
        {
            if (string.IsNullOrWhiteSpace(repositoryUrl) || string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            var regex = new Regex(@"^https?://(www\.)?github\.com/(?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?/?$", RegexOptions.IgnoreCase);
            var match = regex.Match(repositoryUrl.Trim());

            if (!match.Success)
            {
                return null;
            }

            string owner = match.Groups["owner"].Value;
            string repo = match.Groups["repo"].Value;

            try
            {
                string contentUrl = $"https://api.github.com/repos/{owner}/{repo}/contents/{Uri.EscapeDataString(path)}";
                var (contentResponse, contentError) = await SendWithRateLimitCheckAsync(contentUrl);
                if (contentError != null || contentResponse == null)
                {
                    return null;
                }

                var contentJson = await contentResponse.Content.ReadAsStringAsync();
                using var contentDoc = JsonDocument.Parse(contentJson);
                if (contentDoc.RootElement.TryGetProperty("content", out var contentProp))
                {
                    var base64Content = contentProp.GetString() ?? string.Empty;
                    base64Content = base64Content.Replace("\n", "").Replace("\r", "").Trim();
                    var fileBytes = Convert.FromBase64String(base64Content);
                    return Encoding.UTF8.GetString(fileBytes).TrimStart('\uFEFF');
                }
            }
            catch
            {
                // Ignore and return null on failure
            }

            return null;
        }

        private async Task<(HttpResponseMessage? Response, string? ErrorMessage)> SendWithRateLimitCheckAsync(string url)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                var response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    return (response, null);
                }

                // Rate limit check
                if (response.StatusCode == HttpStatusCode.Forbidden || response.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    var hasRateLimitRemaining = response.Headers.TryGetValues("X-RateLimit-Remaining", out var values);
                    if (hasRateLimitRemaining && values != null && values.FirstOrDefault() == "0")
                    {
                        return (null, "GitHub is temporarily unavailable. Please try again in a few minutes.");
                    }
                }

                // Not found or access denied (returns NotFound or Forbidden)
                if (response.StatusCode == HttpStatusCode.NotFound || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    return (null, "This repository could not be accessed. Make sure it's public and the URL is correct.");
                }

                return (null, $"GitHub API returned status code {(int)response.StatusCode}.");
            }
            catch (HttpRequestException)
            {
                return (null, "GitHub is temporarily unavailable. Please try again in a few minutes.");
            }
            catch (Exception)
            {
                return (null, "An unexpected error occurred while communicating with GitHub.");
            }
        }
    }
}
