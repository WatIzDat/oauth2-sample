using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace OpenIddictOAuth.Pages
{
    [Authorize]
    public class ConsentModel : PageModel
    {
        [BindProperty]
        public string ReturnUrl { get; set; }

        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string grant)
        {
            if (!grant.Equals(AuthorizationConstants.GrantAccessValue))
            {
                return Forbid();
            }

            var consentClaim = User.GetClaim(AuthorizationConstants.ConsentNaming);

            if (string.IsNullOrEmpty(consentClaim))
            {
                User.SetClaim(AuthorizationConstants.ConsentNaming, grant);
                await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, User);
            }

            return Redirect(ReturnUrl);
        }
    }
}
