using System;
using System.Linq;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Valkyrie.Data;
using Valkyrie.Models;
using Xunit;

namespace Valkyrie.Tests
{
    /// <summary>
    /// Unit tests verifying Issue #57 Data Protection database persistence configuration,
    /// interface compliance, and entity model non-interference in ApplicationDbContext.
    /// </summary>
    public class DataProtectionTests
    {
        [Fact]
        public void ApplicationDbContext_Implements_IDataProtectionKeyContext()
        {
            // Arrange & Act
            Type dbContextType = typeof(ApplicationDbContext);
            Type interfaceType = typeof(IDataProtectionKeyContext);

            // Assert
            Assert.True(
                interfaceType.IsAssignableFrom(dbContextType),
                $"{nameof(ApplicationDbContext)} must implement {nameof(IDataProtectionKeyContext)} " +
                "to satisfy EF Core Data Protection key persistence constraint.");
        }

        [Fact]
        public void ApplicationDbContext_Exposes_DataProtectionKeysDbSetProperty()
        {
            // Arrange
            var propertyInfo = typeof(ApplicationDbContext).GetProperty(nameof(ApplicationDbContext.DataProtectionKeys));

            // Assert
            Assert.NotNull(propertyInfo);
            Assert.Equal(typeof(DbSet<DataProtectionKey>), propertyInfo.PropertyType);
            Assert.True(propertyInfo.CanRead, "DataProtectionKeys must have a public getter.");
            Assert.True(propertyInfo.CanWrite, "DataProtectionKeys must have a public setter.");
        }

        [Fact]
        public void ApplicationDbContext_Model_RegistersDataProtectionKeyEntityWithKeyAndColumns()
        {
            // Arrange - Build in-memory EF Core model metadata without connecting to SQL Server
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=ValkyrieTestDb;Trusted_Connection=True;")
                .Options;

            using var context = new ApplicationDbContext(options);

            // Act
            var entityType = context.Model.FindEntityType(typeof(DataProtectionKey));

            // Assert
            Assert.NotNull(entityType);

            // Primary key verification
            var primaryKey = entityType.FindPrimaryKey();
            Assert.NotNull(primaryKey);
            Assert.Single(primaryKey.Properties);
            Assert.Equal("Id", primaryKey.Properties[0].Name);

            // Scalar properties verification
            var friendlyNameProp = entityType.FindProperty(nameof(DataProtectionKey.FriendlyName));
            Assert.NotNull(friendlyNameProp);
            Assert.Equal(typeof(string), friendlyNameProp.ClrType);

            var xmlProp = entityType.FindProperty(nameof(DataProtectionKey.Xml));
            Assert.NotNull(xmlProp);
            Assert.Equal(typeof(string), xmlProp.ClrType);
        }

        [Fact]
        public void ApplicationDbContext_Model_PreservesCoreDomainEntitiesAndRelationships()
        {
            // Arrange
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=ValkyrieTestDb;Trusted_Connection=True;")
                .Options;

            using var context = new ApplicationDbContext(options);

            // Assert - Core domain and identity entities remain registered
            var scanResultEntity = context.Model.FindEntityType(typeof(ScanResult));
            var vulnPkgEntity = context.Model.FindEntityType(typeof(VulnerablePackage));
            var codeIssueEntity = context.Model.FindEntityType(typeof(CodeIssue));
            var userEntity = context.Model.FindEntityType(typeof(IdentityUser));

            Assert.NotNull(scanResultEntity);
            Assert.NotNull(vulnPkgEntity);
            Assert.NotNull(codeIssueEntity);
            Assert.NotNull(userEntity);

            // Assert - Foreign key delete behaviors remain intact
            var userFk = Assert.Single(scanResultEntity.GetForeignKeys(), fk => fk.Properties.Any(p => p.Name == nameof(ScanResult.UserId)));
            Assert.Equal(DeleteBehavior.Restrict, userFk.DeleteBehavior);

            var vulnFk = Assert.Single(vulnPkgEntity.GetForeignKeys(), fk => fk.Properties.Any(p => p.Name == nameof(VulnerablePackage.ScanResultId)));
            Assert.Equal(DeleteBehavior.Cascade, vulnFk.DeleteBehavior);

            var codeIssueFk = Assert.Single(codeIssueEntity.GetForeignKeys(), fk => fk.Properties.Any(p => p.Name == nameof(CodeIssue.ScanResultId)));
            Assert.Equal(DeleteBehavior.Cascade, codeIssueFk.DeleteBehavior);
        }
    }
}
