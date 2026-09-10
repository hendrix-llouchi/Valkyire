using System;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Xunit;

namespace Valkyrie.Tests
{
    /// <summary>
    /// Unit tests verifying Issue #58 Application Insights telemetry configuration,
    /// safe unconfigured local development behavior, and non-throwing execution.
    /// </summary>
    public class ApplicationInsightsTests
    {
        [Fact]
        public void TelemetryConfiguration_WhenUnconfigured_HasNullOrEmptyConnectionString()
        {
            // Arrange & Act
            using var config = new TelemetryConfiguration();

            // Assert - In local development without environment variables, connection string is empty
            Assert.True(
                string.IsNullOrEmpty(config.ConnectionString),
                "Unconfigured TelemetryConfiguration must have null or empty ConnectionString.");
        }

        [Fact]
        public void TelemetryClient_WhenUnconfigured_AllowsTrackingCallsWithoutThrowing()
        {
            // Arrange - Create unconfigured client simulating local dev / offline testing environment
            using var config = new TelemetryConfiguration();
            var client = new TelemetryClient(config);

            // Act & Assert - All tracking methods must execute as safe in-memory no-ops without throwing
            var exEvent = Record.Exception(() => client.TrackEvent("LocalDevEvent"));
            var exTrace = Record.Exception(() => client.TrackTrace("LocalDevTrace"));
            var exMetric = Record.Exception(() => client.TrackMetric("LocalDevMetric", 42.0));
            var exException = Record.Exception(() => client.TrackException(new InvalidOperationException("LocalDevException")));
            var exFlush = Record.Exception(() => client.Flush());

            Assert.Null(exEvent);
            Assert.Null(exTrace);
            Assert.Null(exMetric);
            Assert.Null(exException);
            Assert.Null(exFlush);
        }

        [Fact]
        public void TelemetryConfiguration_WhenConnectionStringProvided_BindsCorrectly()
        {
            // Arrange
            using var config = new TelemetryConfiguration();
            const string testConnStr = "InstrumentationKey=00000000-0000-0000-0000-000000000000;IngestionEndpoint=https://eastus-8.in.applicationinsights.azure.com/";

            // Act
            config.ConnectionString = testConnStr;

            // Assert
            Assert.Equal(testConnStr, config.ConnectionString);
        }

        [Fact]
        public void ApplicationInsightsAssembly_IsLoadedAndAccessible()
        {
            // Arrange & Act
            var assembly = typeof(TelemetryClient).Assembly;

            // Assert
            Assert.NotNull(assembly);
            Assert.Equal("Microsoft.ApplicationInsights", assembly.GetName().Name);
        }
    }
}
