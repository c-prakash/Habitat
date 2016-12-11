using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;
using System.Reflection;

namespace Sitecore.Foundation.ClaimsSecurity.Authentication.SwitchingProvider
{
    using System.Collections.Generic;
    using System.Security.Claims;

    public class SwitchingAuthenticationProviderExtension : SwitchingAuthenticationProvider, IClaimsAuthenticationProvider
    {
        protected AuthenticationProvider CurrentProvider
        {
            get
            {
                var baseType = typeof(SwitchingAuthenticationProviderExtension).BaseType;
                if (baseType == null) return null;

                var provider = baseType.GetProperty("CurrentProvider", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly);
                return provider.GetValue(this) as AuthenticationProvider;
            }
        }

        public override User GetActiveUser()
        {
            return CurrentProvider?.GetActiveUser();
        }

        public bool Login(string userName, IEnumerable<Claim> claims)
        {
            var claimsProvider = this.CurrentProvider as IClaimsAuthenticationProvider;
            return claimsProvider != null && claimsProvider.Login(userName, claims);
        }
    }
}