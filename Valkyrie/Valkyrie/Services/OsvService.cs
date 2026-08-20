using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Valkyrie.Models;

namespace Valkyrie.Services
{
    public class OsvService : IOsvService
    {
        private readonly HttpClient _httpClient;

        public OsvService(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _httpClient.Timeout = TimeSpan.FromSeconds(15);
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

            // 2. Prepare the batch request body
            var queries = queryablePackages.Select(p => new
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
                // Failed to contact OSV.dev
                return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
            }

            if (!response.IsSuccessStatusCode)
            {
                return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
            }

            // 3. Parse the batch response
            string jsonResponse;
            try
            {
                jsonResponse = await response.Content.ReadAsStringAsync();
            }
            catch
            {
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
                return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
            }

            if (batchResponse?.Results == null || batchResponse.Results.Count != queryablePackages.Count)
            {
                return (false, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
            }

            // Map vulnerable packages to their vulnerability IDs
            var vulnsToFetch = new HashSet<string>();
            var packageVulnIds = new Dictionary<DependencyPackage, List<string>>();

            for (int i = 0; i < queryablePackages.Count; i++)
            {
                var pkg = queryablePackages[i];
                var result = batchResponse.Results[i];
                if (result.Vulns != null && result.Vulns.Count > 0)
                {
                    var ids = result.Vulns.Select(v => v.Id).Where(id => !string.IsNullOrEmpty(id)).ToList();
                    if (ids.Count > 0)
                    {
                        packageVulnIds[pkg] = ids;
                        foreach (var id in ids)
                        {
                            vulnsToFetch.Add(id);
                        }
                    }
                }
            }

            // 4. Fetch details for each unique vulnerability ID
            var vulnDetails = new Dictionary<string, VulnerabilityDetail>();
            bool detailsFetchPartialFailure = false;

            if (vulnsToFetch.Count > 0)
            {
                var fetchTasks = vulnsToFetch.Select(async id =>
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
                        }
                        else
                        {
                            detailsFetchPartialFailure = true;
                        }
                    }
                    catch
                    {
                        detailsFetchPartialFailure = true;
                    }
                });

                await Task.WhenAll(fetchTasks);
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

            if (detailsFetchPartialFailure)
            {
                return (true, "Some packages could not be checked due to a temporary issue — try rescanning for complete results.");
            }

            return (true, null);
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
