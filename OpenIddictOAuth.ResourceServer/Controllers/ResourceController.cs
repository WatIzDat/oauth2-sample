using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictOAuth.ResourceServer.Controllers
{
    [ApiController]
    [Authorize]
    [Route("[controller]")]
    public class ResourceController : Controller
    {
        [HttpGet]
        public IActionResult Get()
        {
            var claim = User.FindFirst(Claims.Email);

            return Ok($"User: {claim}");
        }
    }
}
