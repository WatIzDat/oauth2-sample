using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddictOAuth.Data;
using System.Collections.Immutable;
using System.Security.Claims;
using System.Web;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictOAuth.Controllers
{
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager applicationManager;
        private readonly IOpenIddictAuthorizationManager authorizationManager;
        private readonly IOpenIddictScopeManager scopeManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthorizationService authorizationService;

        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthorizationService authorizationService)
        {
            this.applicationManager = applicationManager;
            this.authorizationManager = authorizationManager;
            this.scopeManager = scopeManager;
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.authorizationService = authorizationService;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

            var parameters = authorizationService
                .ParseOAuthParameters(HttpContext);

            if (!authorizationService.IsAuthenticated(result, request))
            {
                return Challenge(
                    authenticationSchemes: IdentityConstants.ApplicationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = authorizationService.BuildRedirectUri(HttpContext.Request, parameters)
                    });
            }

            var user = await userManager.GetUserAsync(result.Principal) ??
                throw new InvalidOperationException("The user details cannot be retrieved.");

            var application = await applicationManager.FindByClientIdAsync(request.ClientId) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found");

            var authorizations = await authorizationManager.FindAsync(
                subject: await userManager.GetUserIdAsync(user),
                client: await applicationManager.GetIdAsync(application),
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()).ToListAsync();

            var consentClaim = result.Principal.GetClaim(AuthorizationConstants.ConsentNaming);

            if (consentClaim != AuthorizationConstants.GrantAccessValue)
            {
                var returnUrl = HttpUtility.UrlEncode(authorizationService.BuildRedirectUri(HttpContext.Request, parameters));
                var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

                return Redirect(consentRedirectUrl);
            }

            var userId = result.Principal.FindFirst(ClaimTypes.Email).Value;

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                    .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                    .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                    .SetClaims(Claims.Role, (await userManager.GetRolesAsync(user)).ToImmutableArray());

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            var authorization = authorizations.LastOrDefault();
            authorization ??= await authorizationManager.CreateAsync(
                identity: identity,
                subject: await userManager.GetUserIdAsync(user),
                client: await applicationManager.GetIdAsync(application),
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes());

            identity.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(AuthorizationService.GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            {
                throw new InvalidOperationException("The specified grant type is not supported.");
            }

            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal.GetClaim(Claims.Subject);

            var user = await userManager.FindByIdAsync(userId);

            if (user is null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            if (!await signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));
            }

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                    .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                    .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                    .SetClaims(Claims.Role, (await userManager.GetRolesAsync(user)).ToImmutableArray());

            identity.SetDestinations(AuthorizationService.GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
        public async Task<IActionResult> LogoutPost()
        {
            await signInManager.SignOutAsync();

            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }
    }
}
