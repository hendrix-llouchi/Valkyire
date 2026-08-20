using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Valkyrie.Services
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
            _httpClient.Timeout = TimeSpan.FromSeconds(60);
        }

        private static readonly System.Threading.SemaphoreSlim _rateLimitSemaphore = new System.Threading.SemaphoreSlim(1, 1);
        private static DateTime _lastRequestStartTime = DateTime.MinValue;
        private static readonly TimeSpan _minInterval = TimeSpan.FromMilliseconds(300);

        private async Task AcquireRateLimitSlotAsync()
        {
            await _rateLimitSemaphore.WaitAsync();
            try
            {
                var now = DateTime.UtcNow;
                var timeSinceLast = now - _lastRequestStartTime;
                if (timeSinceLast < _minInterval)
                {
                    var delay = _minInterval - timeSinceLast;
                    await Task.Delay(delay);
                }
                _lastRequestStartTime = DateTime.UtcNow;
            }
            finally
            {
                _rateLimitSemaphore.Release();
            }
        }

        public async Task<(string? Explanation, string? Fix)> ExplainVulnerabilityAsync(
            string packageName, string version, string vulnId, string description)
        {
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
                              $"\n}}";

            return await ExecuteGroqRequestAsync(userContent, packageName, vulnId);
        }

        public async Task<(string? Explanation, string? Fix)> ExplainCodeIssueAsync(
            string fileName, int lineNumber, string issueType, string codeSnippet)
        {
            var userContent = $"Explain the following code security issue:\n" +
                              $"File: {fileName}\n" +
                              $"Line: {lineNumber}\n" +
                              $"Issue Type: {issueType}\n" +
                              $"Code Snippet: {codeSnippet}\n\n" +
                              $"Please provide:\n" +
                              $"1. A plain-English explanation of the security risk (2-3 sentences, no jargon, written for a developer without a security background).\n" +
                              $"2. A specific suggested code fix or pattern to remediate this issue.\n\n" +
                              $"You MUST respond ONLY with a raw JSON object containing exactly the keys 'explanation' and 'fix'. Do not include any markdown formatting, backticks, or wrapping text.\n" +
                              $"Example response:\n" +
                              $"{{\n" +
                              $"  \"explanation\": \"This code contains a hardcoded password...\",\n" +
                              $"  \"fix\": \"Use environment variables or a configuration provider to load the password...\"\n" +
                              $"}}";

            return await ExecuteGroqRequestAsync(userContent, fileName, $"{issueType} @ line {lineNumber}");
        }

        private async Task<(string? Explanation, string? Fix)> ExecuteGroqRequestAsync(
            string userContent, string contextName, string contextId)
        {
            string? apiKey = _configuration["Groq:ApiKey"] ?? _configuration["Grok:ApiKey"];
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                _logger.LogWarning("Groq/Grok API Key is missing. Please set 'Groq:ApiKey' or 'Grok:ApiKey' in configuration.");
                return ("AI analysis could not run: Groq API key is missing. Please add 'Groq__ApiKey' or 'Grok__ApiKey' in your Azure App Settings.", null);
            }

            string model = _configuration["Groq:Model"] ?? "openai/gpt-oss-120b";
            var requestUri = "https://api.groq.com/openai/v1/chat/completions";

            var payloadObj = new
            {
                model = model,
                temperature = 0.2,
                response_format = new { type = "json_object" },
                messages = new[]
                {
                    new { role = "system", content = "You are a security assistant. You must respond ONLY with a raw JSON object containing the keys 'explanation' and 'fix'. Do not include markdown formatting, backticks, or any other wrapper." },
                    new { role = "user", content = userContent }
                }
            };

            string requestJson = JsonSerializer.Serialize(payloadObj);

            int maxAttempts = 3;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                string? responseJson = null;
                try
                {
                    await AcquireRateLimitSlotAsync();

                    using var request = new HttpRequestMessage(HttpMethod.Post, requestUri);
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);
                    request.Content = new StringContent(requestJson, Encoding.UTF8, "application/json");

                    using var response = await _httpClient.SendAsync(request);
                    Console.WriteLine($"[AI DIAG - Groq] Status: {(int)response.StatusCode} for {contextName} ({contextId})");

                    if (!response.IsSuccessStatusCode)
                    {
                        string rawResponse = await response.Content.ReadAsStringAsync();
                        int statusCode = (int)response.StatusCode;
                        Console.WriteLine($"[Groq FAIL] Status: {statusCode} | Body: {rawResponse}");

                        bool isTransient = statusCode == 429 || statusCode == 500 || statusCode == 502 || statusCode == 503 || statusCode == 504;

                        if (isTransient && attempt < maxAttempts)
                        {
                            double delay = Math.Min(4.0, Math.Pow(2, attempt));
                            await Task.Delay(TimeSpan.FromSeconds(delay));
                            continue;
                        }

                        return ($"AI analysis failed: Groq API returned HTTP {statusCode}. Message: {rawResponse[..Math.Min(rawResponse.Length, 150)]}", null);
                    }

                    responseJson = await response.Content.ReadAsStringAsync();

                    using var doc = JsonDocument.Parse(responseJson);
                    var root = doc.RootElement;

                    if (root.TryGetProperty("choices", out var choices) &&
                        choices.ValueKind == JsonValueKind.Array &&
                        choices.GetArrayLength() > 0)
                    {
                        var firstChoice = choices[0];
                        if (firstChoice.TryGetProperty("message", out var messageObj) &&
                            messageObj.TryGetProperty("content", out var contentProp))
                        {
                            string text = contentProp.GetString() ?? "";
                            var result = ParseJsonResponse(text, contextName, contextId);
                            if (!string.IsNullOrWhiteSpace(result.Explanation))
                            {
                                return result;
                            }
                        }
                    }

                    return ("AI analysis failed: Groq API returned an unexpected response structure.", null);
                }
                catch (JsonException)
                {
                    string snippet = responseJson != null ? responseJson[..Math.Min(responseJson.Length, 150)] : "null";
                    return ($"AI analysis failed: Invalid JSON response from Groq. Snippet: {snippet}", null);
                }
                catch (Exception ex) when (IsTransientException(ex) && attempt < maxAttempts)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2));
                }
                catch (Exception ex)
                {
                    return ($"AI analysis failed due to a network error ({ex.GetType().Name}).", null);
                }
            }

            return ("AI analysis failed after all retry attempts.", null);
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

        private (string? Explanation, string? Fix) ParseJsonResponse(string rawResponse, string contextName, string contextId)
        {
            if (string.IsNullOrWhiteSpace(rawResponse))
                return (null, null);

            string cleaned = rawResponse.Trim();

            if (cleaned.StartsWith("```"))
            {
                int firstLineBreak = cleaned.IndexOf('\n');
                if (firstLineBreak != -1)
                {
                    cleaned = cleaned.Substring(firstLineBreak + 1);
                }
                if (cleaned.EndsWith("```"))
                {
                    cleaned = cleaned.Substring(0, cleaned.Length - 3).Trim();
                }
            }

            int firstBrace = cleaned.IndexOf('{');
            int lastBrace = cleaned.LastIndexOf('}');

            if (firstBrace != -1 && lastBrace > firstBrace)
            {
                cleaned = cleaned.Substring(firstBrace, lastBrace - firstBrace + 1);
            }

            try
            {
                var options = new JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    CommentHandling = JsonCommentHandling.Skip
                };

                using var doc = JsonDocument.Parse(cleaned, options);
                var root = doc.RootElement;

                string? explanation = null;
                string? fix = null;

                if (root.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in root.EnumerateObject())
                    {
                        var name = prop.Name.ToLowerInvariant();
                        if (name.Contains("explanation") || name.Contains("risk") || name.Contains("description"))
                        {
                            explanation ??= prop.Value.GetString();
                        }
                        else if (name.Contains("fix") || name.Contains("solution") || name.Contains("remediation") || name.Contains("suggest"))
                        {
                            fix ??= prop.Value.GetString();
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(explanation) || !string.IsNullOrWhiteSpace(fix))
                {
                    return (explanation, fix);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[AI PARSE WARNING] Failed to parse JSON for {ContextName} ({ContextId}). Raw text: {RawText}", contextName, contextId, cleaned);
            }

            return (cleaned, null);
        }
    }
}
