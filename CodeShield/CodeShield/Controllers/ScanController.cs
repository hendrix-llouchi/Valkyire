using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using CodeShield.Models;
using CodeShield.Services;

namespace CodeShield.Controllers
{
    [Authorize]
    public class ScanController : Controller
    {
        private readonly IGitHubService _gitHubService;

        public ScanController(IGitHubService gitHubService)
        {
            _gitHubService = gitHubService;
        }

        [HttpGet]
        [Route("Scan")]
        public IActionResult Index()
        {
            return View(new ScanViewModel());
        }

        [HttpPost]
        [Route("Scan")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ScanViewModel model)
        {
            model.IsSubmitted = true;

            if (string.IsNullOrWhiteSpace(model.RepositoryUrl))
            {
                model.ErrorMessage = "Please enter a valid GitHub repository URL.";
                return View(model);
            }

            var (files, errorMessage) = await _gitHubService.GetRepositoryFilesAsync(model.RepositoryUrl);

            if (errorMessage != null)
            {
                model.ErrorMessage = errorMessage;
            }
            else
            {
                model.Files = files;
            }

            return View(model);
        }
    }
}
