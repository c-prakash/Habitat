namespace Sitecore.Feature.OpenIdConnectRP.Controllers
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Web;
    using Sitecore.Configuration;
    using System.Web.Mvc;
    using IdentityModel;
    using IdentityModel.Client;
    using Microsoft.IdentityModel.Tokens;
    using ScAuthenticationManager = Sitecore.Foundation.ClaimsSecurity.Authentication.ClaimsAuthenticationManager;

    public class AccountsController : Controller
    {
        public string IdentityProviderUrl => Settings.GetSetting("Sitecore.Feature.OpenIdConnectRP.IdentityProviderUrl");

        public string ClientId => Settings.GetSetting("Sitecore.Feature.OpenIdConnectRP.ClientId");

        public string ResponseType => Settings.GetSetting("Sitecore.Feature.OpenIdConnectRP.ResponseType");

        public string Scope => Settings.GetSetting("Sitecore.Feature.OpenIdConnectRP.Scope");

        public string CallbackUrl => Settings.GetSetting("Sitecore.Feature.OpenIdConnectRP.CallbackUrl");

        public string ResponseMode => Settings.GetSetting("Sitecore.Feature.OpenIdConnectRP.ResponseMode");

        public string LoggedInUrl => Settings.GetSetting("Sitecore.Feature.OpenIdConnectRP.LoggedInUrl", "/");

        // GET: Account
        public ActionResult SignIn()
        {
            return this.User.Identity.IsAuthenticated ? View((this.User.Identity as ClaimsIdentity)?.Claims) : this.StartAuthentication();
        }

        [HttpPost]
        public ActionResult SignIn(string id_token, string state)
        {
            var result = HttpContext.Request.Cookies["TempCookie"];
            if (result == null)
            {
                throw new InvalidOperationException("No temp cookie");
            }

            if (string.IsNullOrWhiteSpace(result.Values["state"]) || string.IsNullOrWhiteSpace(result.Values["nonce"]) || !string.Equals(state, result.Values["state"]))
            {
                throw new InvalidOperationException("invalid state or nonce");
            }

            var claimsPrincipal = this.ValidateIdentityToken(id_token, result.Values["nonce"]);
            ScAuthenticationManager.Login(claimsPrincipal);
            HttpContext.Response.Cookies.Remove("TempCookie");

            return this.Redirect(LoggedInUrl);
        }

        public ActionResult SignOut()
        {
            ScAuthenticationManager.Logout();
            var disco = DiscoveryClient.GetAsync(this.IdentityProviderUrl).Result;
            return this.Redirect(disco.EndSessionEndpoint);
        }

        #region private methods

        private ClaimsPrincipal ValidateIdentityToken(string token, string nonce)
        {
            var disco = DiscoveryClient.GetAsync(this.IdentityProviderUrl).Result;
            var keys = new List<SecurityKey>();
            foreach (var webKey in disco.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n }) { KeyId = webKey.Kid };

                keys.Add(key);
            }

            var parameters = new TokenValidationParameters
            {
                ValidAudience = this.ClientId,
                ValidIssuer = this.IdentityProviderUrl,
                IssuerSigningKeys = keys
            };

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            SecurityToken jwt;
            var id = handler.ValidateToken(token, parameters, out jwt);
            if (id.FindFirst("nonce").Value != nonce)
            {
                throw new InvalidOperationException("Invalid nonce");
            }

            return id;
        }

        private ActionResult StartAuthentication()
        {
            var disco = DiscoveryClient.GetAsync(this.IdentityProviderUrl).Result;
            var url = this.GetSignInUrl(disco.AuthorizeEndpoint, this.CallbackUrl);
            return this.Redirect(url);
        }

        private string GetSignInUrl(string authorizeEndpoint, string returnUrl)
        {
            var state = Guid.NewGuid().ToString("N");
            var nonce = Guid.NewGuid().ToString("N");

            var url = authorizeEndpoint +
               "?client_id=" + this.ClientId +
               "&response_type=" + this.ResponseType +
               "&scope=" + this.Scope +
               "&redirect_uri=" + returnUrl +
               "&response_mode=" + this.ResponseMode +
               "&state=" + state +
               "&nonce=" + nonce;

            this.SetTempCookie(state, nonce);

            return url;
        }

        private void SetTempCookie(string state, string nonce)
        {
            var cookie = new HttpCookie("TempCookie");
            cookie.Values.Add("state", state);
            cookie.Values.Add("nonce", nonce);
            HttpContext.Response.Cookies.Add(cookie);
        }

        #endregion private methods
    }
}