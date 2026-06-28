using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace CodeShield.Services
{
    public class AiExplanationService : IAiExplanationService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AiExplanationService> _logger;

        public AiExplanationService(HttpClient httpClient, IConfiguration configuration, ILogger<AiExplanationService> logger)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _logger = logger;
            _httpClient.Timeout = TimeSpan.FromSeconds(25);
        }

        public async Task<(string? Explanation, string? Fix)> ExplainVulnerabilityAsync(
            string packageName, string version, string vulnId, string description)
        {
            string? apiKey = _configuration["AgentRouter:ApiKey"];
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                _logger.LogWarning("AgentRouter API Key is missing. Please set 'AgentRouter:ApiKey' in your configuration (e.g., .NET User Secrets).");
                return (null, null);
            }

            var requestUri = "https://agentrouter.org/v1/messages";

            // Build user prompt
            var userContent = $"Explain the following vulnerability:\n" +
                              $"Package: {packageName}\n" +
                              $"Version: {version}\n" +
                              $"Vulnerability ID: {vulnId}\n" +
                              $"Description: {description}\n\n" +
                              $"Please provide:\n" +
                              $"1. A plain-English explanation of the risk (2-3 sentences, no jargon, written for someone without a security background).\n" +
                              $"2. A specific suggested fix (e.g. which version to upgrade to, or general guidance if no exact safe version is known).\n\n" +
                              $"You MUST respond ONLY with a raw JSON object containing exactly the keys 'explanation' and 'fix'. Do not include any markdown formatting, backticks, or wrapping text.\n" +
                              $"Example response:\n" +
                              $"{{\n" +
                              $"  \"explanation\": \"This package has a vulnerability that allows...\",\n" +
                              $"  \"fix\": \"Upgrade to version 1.2.3 or higher.\"\n" +
                              $"}}";

            var payloadObj = new
            {
                model = "claude-opus-4-6",
                max_tokens = 1024,
                system = "You are a security assistant. You must respond ONLY with a raw JSON object containing the keys 'explanation' and 'fix'. Do not include markdown formatting, backticks, or any other wrapper.",
                messages = new[]
                {
                    new { role = "user", content = userContent }
                }
            };

            string requestJson = JsonSerializer.Serialize(payloadObj);

            int maxAttempts = 5;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, requestUri);
                    request.Headers.Add("x-api-key", apiKey);
                    request.Headers.Add("anthropic-version", "2023-06-01");
                    request.Headers.TryAddWithoutValidation("User-Agent", "claude-code/2.1.131 (cli)");
                    request.Headers.TryAddWithoutValidation("Originator", "codex_cli_rs");
                    request.Content = new StringContent(requestJson, Encoding.UTF8, "application/json");

                    using var response = await _httpClient.SendAsync(request);

                    if (!response.IsSuccessStatusCode)
                    {
                        string rawResponse = await response.Content.ReadAsStringAsync();
                        int statusCode = (int)response.StatusCode;

                        bool isTransient = statusCode == 429 || statusCode == 500 || statusCode == 502 || statusCode == 503 || statusCode == 504;

                        if (isTransient && attempt < maxAttempts)
                        {
                            double delay = Math.Pow(2, attempt) * (0.9 + Random.Shared.NextDouble() * 0.2);
                            _logger.LogWarning(
                                "[AI RETRY] Package={Package} VulnId={VulnId} | Transient HTTP {StatusCode} on attempt {Attempt}/{MaxAttempts}. Retrying in {Delay:F2}s...",
                                packageName, vulnId, statusCode, attempt, maxAttempts, delay);
                            await Task.Delay(TimeSpan.FromSeconds(delay));
                            continue;
                        }

                        _logger.LogError(
                            "[AI FAILURE] Package={Package} Version={Version} VulnId={VulnId} | HTTP {StatusCode} | Body: {Body}",
                            packageName, version, vulnId, statusCode, rawResponse);
                        Console.WriteLine($"[AgentRouter FAIL] {packageName}@{version} ({vulnId}) | Status: {statusCode} | Body: {rawResponse}");
                        return (null, null);
                    }

                    string responseJson = await response.Content.ReadAsStringAsync();

                    using var doc = JsonDocument.Parse(responseJson);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("content", out var contentArray) &&
                        contentArray.ValueKind == JsonValueKind.Array &&
                        contentArray.GetArrayLength() > 0)
                    {
                        var firstContent = contentArray[0];
                        if (firstContent.TryGetProperty("text", out var textProp))
                        {
                            string text = textProp.GetString() ?? "";
                            return ParseJsonResponse(text, packageName, vulnId);
                        }
                    }

                    _logger.LogWarning(
                        "[AI FAILURE] Package={Package} Version={Version} VulnId={VulnId} | Unexpected response format. Response: {Response}",
                        packageName, version, vulnId, responseJson);
                    return (null, null);
                }
                catch (TaskCanceledException) when (attempt < maxAttempts)
                {
                    double delay = Math.Pow(2, attempt) * (0.9 + Random.Shared.NextDouble() * 0.2);
                    _logger.LogWarning(
                        "[AI RETRY] Package={Package} VulnId={VulnId} | Timeout (TaskCanceledException) on attempt {Attempt}/{MaxAttempts}. Retrying in {Delay:F2}s...",
                        packageName, vulnId, attempt, maxAttempts, delay);
                    await Task.Delay(TimeSpan.FromSeconds(delay));
                }
                catch (TaskCanceledException tcEx)
                {
                    string reason = tcEx.CancellationToken.IsCancellationRequested ? "cancelled" : "timed out";
                    _logger.LogError(
                        "[AI FAILURE] Package={Package} Version={Version} VulnId={VulnId} | Request {Reason} (TaskCanceledException). Message: {Message}",
                        packageName, version, vulnId, reason, tcEx.Message);
                    Console.WriteLine($"[AgentRouter FAIL] {packageName}@{version} ({vulnId}) | Request {reason} | {tcEx.Message}");
                    return (null, null);
                }
                catch (Exception ex) when (IsTransientException(ex) && attempt < maxAttempts)
                {
                    double delay = Math.Pow(2, attempt) * (0.9 + Random.Shared.NextDouble() * 0.2);
                    string exTypeName = ex.GetType().Name;
                    _logger.LogWarning(
                        "[AI RETRY] Package={Package} VulnId={VulnId} | Transient Exception {ExType} ({ExMessage}) on attempt {Attempt}/{MaxAttempts}. Retrying in {Delay:F2}s...",
                        packageName, vulnId, exTypeName, ex.Message, attempt, maxAttempts, delay);
                    await Task.Delay(TimeSpan.FromSeconds(delay));
                }
                catch (Exception ex)
                {
                    _logger.LogError(
                        "[AI FAILURE] Package={Package} Version={Version} VulnId={VulnId} | Exception type={ExType} | Message: {Message}",
                        packageName, version, vulnId, ex.GetType().Name, ex.Message);
                    Console.WriteLine($"[AgentRouter FAIL] {packageName}@{version} ({vulnId}) | {ex.GetType().Name}: {ex.Message}");
                    return (null, null);
                }
            }

            return (null, null);
        }

        private static bool IsTransientException(Exception ex)
        {
            if (ex is HttpRequestException || ex is System.IO.IOException || ex is System.Net.Sockets.SocketException)
            {
                return true;
            }
            if (ex.InnerException != null)
            {
                return IsTransientException(ex.InnerException);
            }
            return false;
        }

        private (string? Explanation, string? Fix) ParseJsonResponse(string rawResponse, string packageName, string vulnId)
        {
            if (string.IsNullOrWhiteSpace(rawResponse))
                return (null, null);

            string cleaned = rawResponse.Trim();

            // Strip markdown code block if model wrapped JSON in it
            if (cleaned.StartsWith("```"))
            {
                int firstLineEnd = cleaned.IndexOf('\n');
                if (firstLineEnd != -1)
                {
                    cleaned = cleaned.Substring(firstLineEnd + 1);
                }
                if (cleaned.EndsWith("```"))
                {
                    cleaned = cleaned.Substring(0, cleaned.Length - 3);
                }
                cleaned = cleaned.Trim();
            }

            try
            {
                using var doc = JsonDocument.Parse(cleaned);
                var root = doc.RootElement;

                string? explanation = null;
                if (root.TryGetProperty("explanation", out var expProp))
                {
                    explanation = expProp.GetString();
                }

                string? fix = null;
                if (root.TryGetProperty("fix", out var fixProp))
                {
                    fix = fixProp.GetString();
                }

                return (explanation, fix);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    "[AI FAILURE] Package={Package} VulnId={VulnId} | Failed to parse JSON from AI response. Exception: {ExMessage} | RawContent: {RawContent}",
                    packageName, vulnId, ex.Message, rawResponse);
                Console.WriteLine($"[AgentRouter FAIL] {packageName} ({vulnId}) | JSON parse error: {ex.Message} | Raw: {rawResponse}");
                return (null, null);
            }
        }
    }
}
