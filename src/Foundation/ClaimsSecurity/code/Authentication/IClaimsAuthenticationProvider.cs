namespace Sitecore.Foundation.ClaimsSecurity.Authentication
{
    using System.Collections.Generic;
    using System.Security.Claims;

    public interface IClaimsAuthenticationProvider
    {
        bool Login(string userName, IEnumerable<Claim> claims);
    }
}