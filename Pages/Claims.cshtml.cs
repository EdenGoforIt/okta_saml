using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Okta_SAML_Test.Pages
{
    [Authorize]
    public class ClaimsModel : PageModel
    {
        private readonly ILogger<ClaimsModel> _logger;

        public ClaimsModel(ILogger<ClaimsModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {

        }
    }
}
