using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CodeShield.Data;
using CodeShield.Models;

namespace CodeShield.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;

        public DashboardController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [Route("Dashboard")]
        public async Task<IActionResult> Index()
        {
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(userId))
            {
                return Challenge();
            }

            var scans = await _context.ScanResults
                .Where(s => s.UserId == userId)
                .OrderByDescending(s => s.ScannedAt)
                .ToListAsync();

            int totalScannedRepos = scans.Select(s => s.RepositoryUrl).Distinct().Count();
            int totalIssuesDetected = scans.Sum(s => s.TotalIssuesFound);

            string overallGrade = "N/A";
            if (scans.Any())
            {
                // Most recent scan's security grade
                overallGrade = scans.First().SecurityGrade ?? "A";
            }

            var viewModel = new DashboardViewModel
            {
                TotalScanned = totalScannedRepos,
                TotalIssues = totalIssuesDetected,
                OverallGrade = overallGrade,
                RecentScans = scans.Take(5).ToList()
            };

            return View(viewModel);
        }
    }
}

