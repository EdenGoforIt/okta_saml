using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Authentication;
using Microsoft.Extensions.Options;
using Okta_SAML_Test.Identity;


namespace Okta_SAML_Test.Controllers
{
    [AllowAnonymous]
    [Route("auth")]
    public class AuthController : Controller
    {
        const string _relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration _config;
        public AuthController(IOptions<Saml2Configuration> config)
        {
            _config = config.Value;
        }

        [Route("Login")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Saml2RedirectBinding))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult Login(string? returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string>
        { { _relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });
            return binding.Bind(new Saml2AuthnRequest(_config)).ToActionResult();
        }

        [Route("assertion-consumer-service")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(_config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }

            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);

            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: ClaimsTransform.Transform);
            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.TryGetValue(_relayStateReturnUrl, out var value) ? value : Url.Content("~/");
            return Redirect(returnUrl);
        }



    }

}