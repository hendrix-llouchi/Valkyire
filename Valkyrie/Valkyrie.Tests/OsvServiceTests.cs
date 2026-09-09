using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using Moq.Protected;
using Valkyrie.Models;
using Valkyrie.Services;
using Xunit;

namespace Valkyrie.Tests
{
    public class OsvServiceTests
    {
        [Fact]
        public async Task CheckVulnerabilitiesAsync_UsesCacheOnSubsequentCall_AvoidsHttpCall()
        {
            // Arrange
            var handlerMock = new Mock<HttpMessageHandler>();
            int httpCallCount = 0;

            var batchResponseJson = JsonSerializer.Serialize(new
            {
                results = new[]
                {
                    new
                    {
                        vulns = new[]
                        {
                            new { id = "GHSA-1234-test" }
                        }
                    }
                }
            });

            var vulnDetailJson = JsonSerializer.Serialize(new
            {
                id = "GHSA-1234-test",
                summary = "Test vulnerability",
                database_specific = new { severity = "HIGH" }
            });

            handlerMock.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .Returns<HttpRequestMessage, CancellationToken>((req, ct) =>
                {
                    httpCallCount++;
                    if (req.RequestUri!.ToString().Contains("querybatch"))
                    {
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                        {
                            Content = new StringContent(batchResponseJson)
                        });
                    }

                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(vulnDetailJson)
                    });
                });

            var httpClient = new HttpClient(handlerMock.Object);
            var memoryCache = new MemoryCache(new MemoryCacheOptions());
            var service = new OsvService(httpClient, memoryCache);

            var packagesCall1 = new List<DependencyPackage>
            {
                new DependencyPackage { PackageName = "lodash", Version = "4.17.20", Ecosystem = Ecosystem.Npm }
            };

            var packagesCall2 = new List<DependencyPackage>
            {
                new DependencyPackage { PackageName = "lodash", Version = "4.17.20", Ecosystem = Ecosystem.Npm }
            };

            // Act 1: Initial call should query remote API
            var (success1, error1) = await service.CheckVulnerabilitiesAsync(packagesCall1);

            // Assert 1
            Assert.True(success1);
            Assert.Null(error1);
            Assert.Single(packagesCall1[0].Vulnerabilities);
            Assert.Equal("GHSA-1234-test", packagesCall1[0].Vulnerabilities[0].Id);
            int callsAfterFirst = httpCallCount;
            Assert.True(callsAfterFirst >= 2); // 1 querybatch + 1 detail call

            // Act 2: Repeat call with identical package should be served entirely from memory cache
            var (success2, error2) = await service.CheckVulnerabilitiesAsync(packagesCall2);

            // Assert 2
            Assert.True(success2);
            Assert.Null(error2);
            Assert.Single(packagesCall2[0].Vulnerabilities);
            Assert.Equal("GHSA-1234-test", packagesCall2[0].Vulnerabilities[0].Id);
            Assert.Equal(callsAfterFirst, httpCallCount); // zero additional HTTP calls!
        }

        [Fact]
        public async Task CheckVulnerabilitiesAsync_PartialCacheHit_OnlyQueriesUncachedPackages()
        {
            // Arrange
            var handlerMock = new Mock<HttpMessageHandler>();
            int batchCallCount = 0;

            var batchResponseJson = JsonSerializer.Serialize(new
            {
                results = new[]
                {
                    new
                    {
                        vulns = new[] { new { id = "GHSA-pkg2-vuln" } }
                    }
                }
            });

            var vulnDetailJson = JsonSerializer.Serialize(new
            {
                id = "GHSA-pkg2-vuln",
                summary = "Vulnerability in pkg2",
                database_specific = new { severity = "LOW" }
            });

            handlerMock.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .Returns<HttpRequestMessage, CancellationToken>((req, ct) =>
                {
                    if (req.RequestUri!.ToString().Contains("querybatch"))
                    {
                        batchCallCount++;
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                        {
                            Content = new StringContent(batchResponseJson)
                        });
                    }

                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(vulnDetailJson)
                    });
                });

            var httpClient = new HttpClient(handlerMock.Object);
            var memoryCache = new MemoryCache(new MemoryCacheOptions());

            // Pre-seed cache with pkg1 (clean)
            memoryCache.Set("osv:pkg:Npm:pkg1:1.0.0", new List<string>());

            var service = new OsvService(httpClient, memoryCache);

            var packages = new List<DependencyPackage>
            {
                new DependencyPackage { PackageName = "pkg1", Version = "1.0.0", Ecosystem = Ecosystem.Npm },
                new DependencyPackage { PackageName = "pkg2", Version = "2.0.0", Ecosystem = Ecosystem.Npm }
            };

            // Act
            var (success, error) = await service.CheckVulnerabilitiesAsync(packages);

            // Assert
            Assert.True(success);
            Assert.Null(error);
            Assert.Empty(packages[0].Vulnerabilities); // pkg1 cached as clean
            Assert.Single(packages[1].Vulnerabilities); // pkg2 found vuln
            Assert.Equal(1, batchCallCount); // Batch call only queried pkg2
        }

        [Fact]
        public async Task CheckVulnerabilitiesAsync_WorksWithoutCacheInstance_ReturnsResultsGracefully()
        {
            // Arrange
            var handlerMock = new Mock<HttpMessageHandler>();
            var batchResponseJson = JsonSerializer.Serialize(new
            {
                results = new[]
                {
                    new
                    {
                        vulns = new[] { new { id = "GHSA-no-cache" } }
                    }
                }
            });

            var vulnDetailJson = JsonSerializer.Serialize(new
            {
                id = "GHSA-no-cache",
                summary = "Vulnerability without cache",
                database_specific = new { severity = "CRITICAL" }
            });

            handlerMock.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .Returns<HttpRequestMessage, CancellationToken>((req, ct) =>
                {
                    if (req.RequestUri!.ToString().Contains("querybatch"))
                    {
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                        {
                            Content = new StringContent(batchResponseJson)
                        });
                    }

                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(vulnDetailJson)
                    });
                });

            var httpClient = new HttpClient(handlerMock.Object);
            // Pass null for IMemoryCache
            var service = new OsvService(httpClient, cache: null);

            var packages = new List<DependencyPackage>
            {
                new DependencyPackage { PackageName = "pkg-null-cache", Version = "1.0.0", Ecosystem = Ecosystem.Npm }
            };

            // Act
            var (success, error) = await service.CheckVulnerabilitiesAsync(packages);

            // Assert
            Assert.True(success);
            Assert.Null(error);
            Assert.Single(packages[0].Vulnerabilities);
            Assert.Equal("GHSA-no-cache", packages[0].Vulnerabilities[0].Id);
            Assert.Equal(Severity.Critical, packages[0].Vulnerabilities[0].Severity);
        }

        [Fact]
        public async Task CheckVulnerabilitiesAsync_NullOrEmptyVersion_HandlesGracefullyWithoutThrowing()
        {
            // Arrange
            var handlerMock = new Mock<HttpMessageHandler>();
            var batchResponseJson = JsonSerializer.Serialize(new
            {
                results = new[]
                {
                    new { vulns = Array.Empty<object>() }
                }
            });

            handlerMock.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(batchResponseJson)
                });

            var httpClient = new HttpClient(handlerMock.Object);
            var memoryCache = new MemoryCache(new MemoryCacheOptions());
            var service = new OsvService(httpClient, memoryCache);

            var packages = new List<DependencyPackage>
            {
                new DependencyPackage { PackageName = "pkg-no-version", Version = null!, Ecosystem = Ecosystem.Npm }
            };

            // Act & Assert - should not throw NullReferenceException
            var (success, error) = await service.CheckVulnerabilitiesAsync(packages);
            Assert.True(success);
            Assert.Null(error);
        }

        [Fact]
        public async Task CheckVulnerabilitiesAsync_PartialRemoteFailure_PreservesPrecachedVulnerabilities()
        {
            // Arrange
            var handlerMock = new Mock<HttpMessageHandler>();

            handlerMock.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.InternalServerError)); // OSV down

            var httpClient = new HttpClient(handlerMock.Object);
            var memoryCache = new MemoryCache(new MemoryCacheOptions());

            // Pre-cache pkg1 with a known vulnerability
            memoryCache.Set("osv:pkg:Npm:pkg-cached:1.0.0", new List<string> { "GHSA-cached-vuln" });
            memoryCache.Set("osv:vuln:GHSA-CACHED-VULN", new VulnerabilityDetail
            {
                Id = "GHSA-cached-vuln",
                Description = "Pre-cached vulnerability details",
                Severity = Severity.High
            });

            var service = new OsvService(httpClient, memoryCache);

            var packages = new List<DependencyPackage>
            {
                new DependencyPackage { PackageName = "pkg-cached", Version = "1.0.0", Ecosystem = Ecosystem.Npm },
                new DependencyPackage { PackageName = "pkg-uncached", Version = "2.0.0", Ecosystem = Ecosystem.Npm }
            };

            // Act
            var (success, error) = await service.CheckVulnerabilitiesAsync(packages);

            // Assert: Partial failure returned
            Assert.False(success);
            Assert.NotNull(error);
            // Pre-cached package vulnerabilities are preserved!
            Assert.Single(packages[0].Vulnerabilities);
            Assert.Equal("GHSA-cached-vuln", packages[0].Vulnerabilities[0].Id);
            Assert.Equal(Severity.High, packages[0].Vulnerabilities[0].Severity);
        }
    }
}
