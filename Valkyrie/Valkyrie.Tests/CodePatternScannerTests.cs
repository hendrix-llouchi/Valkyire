using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Moq;
using Valkyrie.Models;
using Valkyrie.Services;

namespace Valkyrie.Tests
{
    public class CodePatternScannerTests
    {
        private readonly Mock<IGitHubService> _mockGitHubService;
        private readonly CodePatternScanner _scanner;

        public CodePatternScannerTests()
        {
            _mockGitHubService = new Mock<IGitHubService>();
            _scanner = new CodePatternScanner(_mockGitHubService.Object);
        }

        [Fact]
        public async Task ScanAsync_DetectsHardcodedSecret_InJavaFile()
        {
            // Arrange
            string repoUrl = "https://github.com/test/repo";
            string fileName = "App.java";
            string fileContent = "public class App {\n    private String apiKey = \"secret_api_key_12345678\";\n}";

            _mockGitHubService
                .Setup(s => s.GetFileContentAsync(repoUrl, fileName))
                .ReturnsAsync(fileContent);

            var files = new List<string> { fileName };
            var ecosystems = new List<Ecosystem> { Ecosystem.Maven };

            // Act
            var issues = await _scanner.ScanAsync(repoUrl, files, ecosystems);

            // Assert
            Assert.NotEmpty(issues);
            Assert.Contains(issues, i => i.IssueType == IssueType.HardcodedSecret);
        }

        [Fact]
        public async Task ScanAsync_DetectsSqlInjection_InGoFile()
        {
            // Arrange
            string repoUrl = "https://github.com/test/repo";
            string fileName = "main.go";
            string fileContent = "package main\n\nimport \"fmt\"\n\nfunc main() {\n    query := \"SELECT * FROM users WHERE id = \" + userId\n}";

            _mockGitHubService
                .Setup(s => s.GetFileContentAsync(repoUrl, fileName))
                .ReturnsAsync(fileContent);

            var files = new List<string> { fileName };
            var ecosystems = new List<Ecosystem> { Ecosystem.Go };

            // Act
            var issues = await _scanner.ScanAsync(repoUrl, files, ecosystems);

            // Assert
            Assert.NotEmpty(issues);
            Assert.Contains(issues, i => i.IssueType == IssueType.SqlInjectionRisk);
        }

        [Fact]
        public async Task ScanAsync_DetectsInsecureHttp_InPhpFile()
        {
            // Arrange
            string repoUrl = "https://github.com/test/repo";
            string fileName = "config.php";
            string fileContent = "<?php\n$apiUrl = 'http://api.insecure-service.com/v1';\n?>";

            _mockGitHubService
                .Setup(s => s.GetFileContentAsync(repoUrl, fileName))
                .ReturnsAsync(fileContent);

            var files = new List<string> { fileName };
            var ecosystems = new List<Ecosystem> { Ecosystem.PHP };

            // Act
            var issues = await _scanner.ScanAsync(repoUrl, files, ecosystems);

            // Assert
            Assert.NotEmpty(issues);
            Assert.Contains(issues, i => i.IssueType == IssueType.InsecureHttp);
        }
    }
}
