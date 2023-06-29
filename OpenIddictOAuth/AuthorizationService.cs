using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictOAuth
{
    public class AuthorizationService
    {
        public static List<string> GetDestinations(Claim claim)
        {
            var destinations = new List<string>();

            if (claim.Type is Claims.Name or Claims.Email)
            {
                destinations.Add(Destinations.AccessToken);
            }

            return destinations;
        }

        public string BuildRedirectUri(HttpRequest request, IDictionary<string, StringValues> parameters)
        {
            string uri = request.PathBase + request.Path + QueryString.Create(parameters);

            return uri;
        }

        public IDictionary<string, StringValues> ParseOAuthParameters(HttpContext httpContext, List<string>? excluding = null)
        {
            excluding ??= new List<string>();

            var parameters = httpContext.Request.HasFormContentType
                ? httpContext.Request.Form
                    .Where(parameter => !excluding.Contains(parameter.Key))
                    .ToDictionary(keyValuePair => keyValuePair.Key, keyValuePair => keyValuePair.Value)
                : httpContext.Request.Query
                    .Where(parameter => !excluding.Contains(parameter.Key))
                    .ToDictionary(keyValuePair => keyValuePair.Key, keyValuePair => keyValuePair.Value);

            return parameters;
        }

        public bool IsAuthenticated(AuthenticateResult result, OpenIddictRequest request)
        {
            if (!result.Succeeded)
            {
                return false;
            }

            if (request.MaxAge.HasValue && result.Properties is not null)
            {
                var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);

                bool isExpired = !result.Properties.IssuedUtc.HasValue ||
                    DateTimeOffset.UtcNow - result.Properties.IssuedUtc > maxAgeSeconds;

                if (isExpired)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
