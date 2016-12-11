namespace Sitecore.Foundation.ClaimsSecurity.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Services;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Claims;
    using Sitecore.Configuration;
    using Sitecore.Security.Authentication;

    public static class ClaimsAuthenticationManager
    {
        /// <summary>Provider helpers map.</summary>
        private static readonly ProviderHelper<AuthenticationProvider, AuthenticationProviderCollection> data = new ProviderHelper<AuthenticationProvider, AuthenticationProviderCollection>("authentication");

        /// <summary>Gets the provider.</summary>
        /// <value>The provider.</value>
        public static AuthenticationProvider Provider
        {
            get
            {
                return data.Provider;
            }
        }

        /// <summary>Gets all providers.</summary>
        /// <value>The providers.</value>
        public static AuthenticationProviderCollection Providers
        {
            get
            {
                return data.Providers;
            }
        }

        public static bool Login(string userName, IEnumerable<Claim> claims)
        {
            var clamValues = claims as Claim[] ?? claims.ToArray();
            if (string.IsNullOrEmpty(userName))
            {
                var nameClaim = clamValues.FirstOrDefault(c => c.Type == ClaimTypes.Name);
                userName = nameClaim != null ? nameClaim.Value : clamValues.FirstOrDefault(c => c.Type == "sub")?.Value;
            }

            var claimsAuthenticationProvider = Provider as IClaimsAuthenticationProvider;
            if (claimsAuthenticationProvider == null)
                throw new Exception("Claims Authentication Provider can not be null.");

            return claimsAuthenticationProvider.Login(userName, clamValues);
        }

        public static bool Login(ClaimsPrincipal claimsPrincipal)
        {
            return Login(claimsPrincipal.Identity.Name, claimsPrincipal.Claims);
        }

        public static void Logout()
        {
            SessionSecurityToken sessionToken;
            if (!FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken))
            {
                // Clean up
            }
            Provider.Logout();
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
        }
    }
}