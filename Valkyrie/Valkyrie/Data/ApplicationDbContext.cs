using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Valkyrie.Models;

namespace Valkyrie.Data
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>, IDataProtectionKeyContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<ScanResult> ScanResults { get; set; } = null!;
        public DbSet<VulnerablePackage> VulnerablePackages { get; set; } = null!;
        public DbSet<CodeIssue> CodeIssues { get; set; } = null!;
        public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure relationship between ScanResult and IdentityUser
            modelBuilder.Entity<ScanResult>()
                .HasOne(s => s.User)
                .WithMany()
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            // Configure ScanResult -> VulnerablePackages cascade delete
            modelBuilder.Entity<VulnerablePackage>()
                .HasOne(vp => vp.ScanResult)
                .WithMany(s => s.VulnerablePackages)
                .HasForeignKey(vp => vp.ScanResultId)
                .OnDelete(DeleteBehavior.Cascade);

            // Configure ScanResult -> CodeIssues cascade delete
            modelBuilder.Entity<CodeIssue>()
                .HasOne(ci => ci.ScanResult)
                .WithMany(s => s.CodeIssues)
                .HasForeignKey(ci => ci.ScanResultId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
