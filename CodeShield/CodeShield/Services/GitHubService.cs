using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

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

        public async Task<(List<string>? Files, string? ErrorMessage)> GetRepositoryFilesAsync(string repositoryUrl)
        {
            if (string.IsNullOrWhiteSpace(repositoryUrl))
            {
                return (null, "Please enter a valid GitHub repository URL.");
            }

            // Validate and parse GitHub URL
            var regex = new Regex(@"^https?://(www\.)?github\.com/(?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?/?$", RegexOptions.IgnoreCase);
            var match = regex.Match(repositoryUrl.Trim());

            if (!match.Success)
            {
                return (null, "Please enter a valid GitHub repository URL.");
            }

            string owner = match.Groups["owner"].Value;
            string repo = match.Groups["repo"].Value;

            // 1. Get repository details to verify existence, public status, and default branch
            string repoUrl = $"https://api.github.com/repos/{owner}/{repo}";
            var (repoResponse, repoError) = await SendWithRateLimitCheckAsync(repoUrl);

            if (repoError != null)
            {
                return (null, repoError);
            }

            if (repoResponse == null)
            {
                return (null, "This repository could not be accessed. Make sure it's public and the URL is correct.");
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
                return (null, "Failed to parse repository information from GitHub API.");
            }

            // 2. Fetch the recursive git tree for the default branch
            string treeUrl = $"https://api.github.com/repos/{owner}/{repo}/git/trees/{defaultBranch}?recursive=1";
            var (treeResponse, treeError) = await SendWithRateLimitCheckAsync(treeUrl);

            if (treeError != null)
            {
                return (null, treeError);
            }

            if (treeResponse == null)
            {
                return (null, "Failed to retrieve the file list from GitHub.");
            }

            try
            {
                var treeJson = await treeResponse.Content.ReadAsStringAsync();
                using var treeDoc = JsonDocument.Parse(treeJson);
                if (!treeDoc.RootElement.TryGetProperty("tree", out var treeElement))
                {
                    return (null, "Failed to parse file tree. The repository might be empty.");
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
                    return (null, "This repository is too large to scan in full. CodeShield currently supports repositories up to 1000 files.");
                }

                return (files, null);
            }
            catch (Exception)
            {
                return (null, "An error occurred while parsing the repository files.");
            }
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
