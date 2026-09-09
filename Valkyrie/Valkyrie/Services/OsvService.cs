using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Valkyrie.Models;

namespace Valkyrie.Services
{
    public class OsvService : IOsvService
    {
        private readonly HttpClient _httpClient;
        private readonly IMemoryCache? _cache;

        private static readonly TimeSpan PackageCacheDuration = TimeSpan.FromHours(2);
        private static readonly TimeSpan PackageSlidingExpiration = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan VulnDetailCacheDuration = TimeSpan.FromHours(6);

        public OsvService(HttpClient httpClient, IMemoryCache? cache = null)
        {
            _httpClient = httpClient;
            _httpClient.Timeout = TimeSpan.FromSeconds(15);
            _cache = cache;
        }

        private static string GetPackageCacheKey(DependencyPackage package)
        {
            string pkgName = package.PackageName?.Trim().ToLowerInvariant() ?? string.Empty;
            string version = package.Version?.Trim().ToLowerInvariant() ?? string.Empty;
            return $"osv:pkg:{package.Ecosystem}:{pkgName}:{version}";
        }

        private static string GetVulnDetailCacheKey(string vulnId)
        {
            return $"osv:vuln:{vulnId.Trim().ToUpperInvariant()}";
        }

        public async Task<(bool Success, string? ErrorMessage)> CheckVulnerabilitiesAsync(List<DependencyPackage> packages)
        {
            if (packages == null || packages.Count == 0)
            {
                return (true, null);
            }

            // 1. All parsed ecosystems can be queried against OSV.dev
            var queryablePackages = packages
                .Where(p => !string.IsNullOrWhiteSpace(p.PackageName))
                .ToList();

            if (queryablePackages.Count == 0)
            {
                return (true, null);
            }

            // 2. Check cache for packages already resolved
            var uncachedPackages = new List<DependencyPackage>();
            var packageVulnIds = new Dictionary<DependencyPackage, List<string>>();
            var vulnsToFetch = new HashSet<string>();

            foreach (var pkg in queryablePackages)
            {
                string cacheKey = GetPackageCacheKey(pkg);
                if (_cache != null && _cache.TryGetValue(cacheKey, out List<string>? cachedIds) && cachedIds != null)
                {
                    if (cachedIds.Count > 0)
                    {
                        packageVulnIds[pkg] = cachedIds;
                        foreach (var id in cachedIds)
                        {
                            vulnsToFetch.Add(id);
                        }
                    }
                }
                else
                {
                    uncachedPackages.Add(pkg);
                }
            }

            // 3. Query OSV.dev batch endpoint for uncached packages only (deduplicating identical package queries)
            if (uncachedPackages.Count > 0)
            {
                var uniqueUncachedTuples = uncachedPackages
                    .GroupBy(p => (p.Ecosystem, Name: p.PackageName.Trim(), Version: p.Version?.Trim() ?? string.Empty))
                    .Select(g => g.First())
                    .ToList();

                var queries = uniqueUncachedTuples.Select(p => new
                {
                    package = new
                    {
                        name = p.PackageName,
                        ecosystem = p.Ecosystem switch
                        {
                            Ecosystem.Npm => "npm",
                            Ecosystem.NuGet => "NuGet",
                            Ecosystem.Python => "PyPI",
                            Ecosystem.Maven => "Maven",
                            Ecosystem.Go => "Go",
                            Ecosystem.Ruby => "RubyGems",
                            Ecosystem.PHP => "Packagist",
                            _ => p.Ecosystem.ToString()
                        }
                    },
                    version = p.Version
                }).ToList();

                var requestBody = new { queries };
                string jsonRequest = JsonSerializer.Serialize(requestBody);

                HttpResponseMessage response;
                try
                {
                    var content = new StringContent(jsonRequest, Encoding.UTF8, "application/json");
                    response = await _httpClient.PostAsync("https://api.osv.dev/v1/querybatch", content);
                }
                catch (Exception)
                {
                    // If we have some cached results, still populate them before failing/warning
                    PopulateCachedVulnerabilities(packageVulnIds);
                    return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
                }

                if (!response.IsSuccessStatusCode)
                {
                    PopulateCachedVulnerabilities(packageVulnIds);
                    return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
                }

                string jsonResponse;
                try
                {
                    jsonResponse = await response.Content.ReadAsStringAsync();
                }
                catch
                {
                    PopulateCachedVulnerabilities(packageVulnIds);
                    return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
                }

                OsvBatchResponse? batchResponse;
                try
                {
                    batchResponse = JsonSerializer.Deserialize<OsvBatchResponse>(jsonResponse, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                }
                catch
                {
                    PopulateCachedVulnerabilities(packageVulnIds);
                    return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
                }

                if (batchResponse?.Results == null || batchResponse.Results.Count != uniqueUncachedTuples.Count)
                {
                    PopulateCachedVulnerabilities(packageVulnIds);
                    return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
                }

                // Map results back to unique package tuples
                var tupleVulnMap = new Dictionary<(Ecosystem, string, string), List<string>>();

                for (int i = 0; i < uniqueUncachedTuples.Count; i++)
                {
                    var tuplePkg = uniqueUncachedTuples[i];
                    var result = batchResponse.Results[i];
                    var ids = new List<string>();

                    if (result.Vulns != null && result.Vulns.Count > 0)
                    {
                        ids = result.Vulns
                            .Select(v => v.Id)
                            .Where(id => !string.IsNullOrEmpty(id))
                            .Distinct()
                            .ToList();
                    }

                    var key = (tuplePkg.Ecosystem, tuplePkg.PackageName.Trim(), tuplePkg.Version?.Trim() ?? string.Empty);
                    tupleVulnMap[key] = ids;

                    // Cache the vulnerability IDs for this package (empty list if clean)
                    if (_cache != null)
                    {
                        string cacheKey = GetPackageCacheKey(tuplePkg);
                        _cache.Set(cacheKey, ids, new MemoryCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = PackageCacheDuration,
                            SlidingExpiration = PackageSlidingExpiration
                        });
                    }
                }

                // Assign back to each uncached package instance
                foreach (var pkg in uncachedPackages)
                {
                    var key = (pkg.Ecosystem, pkg.PackageName.Trim(), pkg.Version?.Trim() ?? string.Empty);
                    if (tupleVulnMap.TryGetValue(key, out var ids) && ids.Count > 0)
                    {
                        packageVulnIds[pkg] = ids;
                        foreach (var id in ids)
                        {
                            vulnsToFetch.Add(id);
                        }
                    }
                }
            }

            // 4. Fetch details for each unique vulnerability ID (using cache where available, throttled)
            var vulnDetails = new Dictionary<string, VulnerabilityDetail>();
            var vulnsToFetchRemotely = new List<string>();

            foreach (var id in vulnsToFetch)
            {
                string detailCacheKey = GetVulnDetailCacheKey(id);
                if (_cache != null && _cache.TryGetValue(detailCacheKey, out VulnerabilityDetail? cachedDetail) && cachedDetail != null)
                {
                    vulnDetails[id] = cachedDetail;
                }
                else
                {
                    vulnsToFetchRemotely.Add(id);
                }
            }

            int detailsFetchFailed = 0;

            if (vulnsToFetchRemotely.Count > 0)
            {
                var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = 8 };
                await Parallel.ForEachAsync(vulnsToFetchRemotely, parallelOptions, async (id, ct) =>
                {
                    try
                    {
                        var detail = await FetchVulnerabilityDetailAsync(id);
                        if (detail != null)
                        {
                            lock (vulnDetails)
                            {
                                vulnDetails[id] = detail;
                            }

                            if (_cache != null)
                            {
                                string detailCacheKey = GetVulnDetailCacheKey(id);
                                _cache.Set(detailCacheKey, detail, new MemoryCacheEntryOptions
                                {
                                    AbsoluteExpirationRelativeToNow = VulnDetailCacheDuration
                                });
                            }
                        }
                        else
                        {
                            Interlocked.Exchange(ref detailsFetchFailed, 1);
                        }
                    }
                    catch
                    {
                        Interlocked.Exchange(ref detailsFetchFailed, 1);
                    }
                });
            }

            // 5. Populate vulnerabilities on packages
            foreach (var kvp in packageVulnIds)
            {
                var pkg = kvp.Key;
                var ids = kvp.Value;

                foreach (var id in ids)
                {
                    if (vulnDetails.TryGetValue(id, out var detail))
                    {
                        pkg.Vulnerabilities.Add(new VulnerabilityDetail
                        {
                            Id = detail.Id,
                            Description = detail.Description,
                            Severity = detail.Severity
                        });
                    }
                    else
                    {
                        // Default to a placeholder detail if we couldn't load details
                        pkg.Vulnerabilities.Add(new VulnerabilityDetail
                        {
                            Id = id,
                            Description = "Details could not be retrieved from OSV.dev.",
                            Severity = Severity.Medium
                        });
                    }
                }
            }

            if (detailsFetchFailed == 1)
            {
                return (true, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
            }

            return (true, null);
        }

        private void PopulateCachedVulnerabilities(Dictionary<DependencyPackage, List<string>> packageVulnIds)
        {
            if (packageVulnIds.Count == 0) return;

            foreach (var kvp in packageVulnIds)
            {
                var pkg = kvp.Key;
                foreach (var id in kvp.Value)
                {
                    string detailCacheKey = GetVulnDetailCacheKey(id);
                    if (_cache != null && _cache.TryGetValue(detailCacheKey, out VulnerabilityDetail? detail) && detail != null)
                    {
                        pkg.Vulnerabilities.Add(new VulnerabilityDetail
                        {
                            Id = detail.Id,
                            Description = detail.Description,
                            Severity = detail.Severity
                        });
                    }
                    else
                    {
                        pkg.Vulnerabilities.Add(new VulnerabilityDetail
                        {
                            Id = id,
                            Description = "Details could not be retrieved from OSV.dev.",
                            Severity = Severity.Medium
                        });
                    }
                }
            }
        }

        private async Task<VulnerabilityDetail?> FetchVulnerabilityDetailAsync(string id)
        {
            try
            {
                var response = await _httpClient.GetAsync($"https://api.osv.dev/v1/vulns/{Uri.EscapeDataString(id)}");
                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }

                string json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                // Extract summary/description
                string summary = "";
                if (root.TryGetProperty("summary", out var summaryProp))
                {
                    summary = summaryProp.GetString() ?? "";
                }

                string details = "";
                if (root.TryGetProperty("details", out var detailsProp))
                {
                    details = detailsProp.GetString() ?? "";
                }

                string description = !string.IsNullOrWhiteSpace(summary) ? summary : details;
                if (string.IsNullOrWhiteSpace(description))
                {
                    description = "No description available.";
                }

                // Determine severity
                Severity severity = Severity.Medium; // default
                bool severityFound = false;

                // 1. Check database_specific.severity
                if (root.TryGetProperty("database_specific", out var dbSpec) && dbSpec.ValueKind == JsonValueKind.Object)
                {
                    if (dbSpec.TryGetProperty("severity", out var dbSeverityProp))
                    {
                        string? dbSeverity = dbSeverityProp.GetString();
                        if (!string.IsNullOrEmpty(dbSeverity))
                        {
                            severity = MapSeverityString(dbSeverity);
                            severityFound = true;
                        }
                    }
                }

                // 2. Fall back to parsing CVSS v3 score from severity array
                if (!severityFound && root.TryGetProperty("severity", out var severityArray) && severityArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in severityArray.EnumerateArray())
                    {
                        if (item.TryGetProperty("type", out var typeProp) && typeProp.GetString()?.StartsWith("CVSS_V3", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            if (item.TryGetProperty("score", out var scoreProp))
                            {
                                string? vector = scoreProp.GetString();
                                if (!string.IsNullOrEmpty(vector))
                                {
                                    double score = CalculateCvss3BaseScore(vector);
                                    severity = score switch
                                    {
                                        >= 9.0 => Severity.Critical,
                                        >= 7.0 => Severity.High,
                                        >= 4.0 => Severity.Medium,
                                        _ => Severity.Low
                                    };
                                    severityFound = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                return new VulnerabilityDetail
                {
                    Id = id,
                    Description = description,
                    Severity = severity
                };
            }
            catch
            {
                return null;
            }
        }

        private Severity MapSeverityString(string sev)
        {
            return sev.ToUpperInvariant() switch
            {
                "CRITICAL" => Severity.Critical,
                "HIGH" => Severity.High,
                "MODERATE" => Severity.Medium,
                "MEDIUM" => Severity.Medium,
                "LOW" => Severity.Low,
                _ => Severity.Medium
            };
        }

        private double CalculateCvss3BaseScore(string vector)
        {
            try
            {
                var parts = vector.Split('/');
                var metrics = new Dictionary<string, string>();
                foreach (var part in parts)
                {
                    var kv = part.Split(':');
                    if (kv.Length == 2)
                    {
                        metrics[kv[0].Trim().ToUpperInvariant()] = kv[1].Trim().ToUpperInvariant();
                    }
                }

                string av = metrics.GetValueOrDefault("AV", "N");
                string ac = metrics.GetValueOrDefault("AC", "L");
                string pr = metrics.GetValueOrDefault("PR", "N");
                string ui = metrics.GetValueOrDefault("UI", "N");
                string s = metrics.GetValueOrDefault("S", "U");
                string c = metrics.GetValueOrDefault("C", "N");
                string i = metrics.GetValueOrDefault("I", "N");
                string a = metrics.GetValueOrDefault("A", "N");

                double avVal = av switch { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => 0.85 };
                double acVal = ac switch { "L" => 0.77, "H" => 0.44, _ => 0.77 };

                bool scopeChanged = s == "C";
                double prVal = pr switch
                {
                    "N" => 0.85,
                    "L" => scopeChanged ? 0.68 : 0.62,
                    "H" => scopeChanged ? 0.50 : 0.27,
                    _ => 0.85
                };
                double uiVal = ui switch { "N" => 0.85, "R" => 0.62, _ => 0.85 };

                double cVal = c switch { "H" => 0.56, "L" => 0.22, _ => 0.0 };
                double iVal = i switch { "H" => 0.56, "L" => 0.22, _ => 0.0 };
                double aVal = a switch { "H" => 0.56, "L" => 0.22, _ => 0.0 };

                double exploitability = 8.22 * avVal * acVal * prVal * uiVal;
                double impactMultiplier = 1 - (1 - cVal) * (1 - iVal) * (1 - aVal);

                if (impactMultiplier <= 0) return 0.0;

                double impact;
                double baseScore;
                if (!scopeChanged)
                {
                    impact = 6.42 * impactMultiplier;
                    baseScore = Math.Min(Math.Ceiling((impact + exploitability) * 10) / 10.0, 10.0);
                }
                else
                {
                    impact = 7.52 * (impactMultiplier - 0.029) - 3.25 * Math.Pow(impactMultiplier - 0.02, 15);
                    baseScore = Math.Min(Math.Ceiling(1.08 * (impact + exploitability) * 10) / 10.0, 10.0);
                }

                return baseScore;
            }
            catch
            {
                return 5.0; // default to medium if vector parsing fails unexpectedly
            }
        }
    }

    // Helper classes for deserialization
    public class OsvBatchResponse
    {
        public List<OsvQueryResult>? Results { get; set; }
    }

    public class OsvQueryResult
    {
        public List<OsvVulnShort>? Vulns { get; set; }
    }

    public class OsvVulnShort
    {
        public string Id { get; set; } = string.Empty;
        public string Modified { get; set; } = string.Empty;
    }
}
