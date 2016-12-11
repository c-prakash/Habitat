/*
 --------------------------------------------------------------
 ***** Source code taken from *****
 http://webcmd.wordpress.com/2012/07/09/federated-authentication-with-sitecore-and-the-windows-identity-foundation/
 --------------------------------------------------------------
 */

using System.Collections.Specialized;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Sitecore.Diagnostics;
using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;

namespace Sitecore.Foundation.ClaimsSecurity.Authentication.Provider
{
    using System.Collections.Generic;
    using System.Linq;
    using Sitecore.Foundation.ClaimsSecurity.Authentication.Helper;

    public class ClaimsAuthenticationProvider : MembershipAuthenticationProvider, IClaimsAuthenticationProvider
    {
        #region Fields

        private ClaimsAuthenticationHelper helper;

        private const string IdentityProvider = "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider";

        #endregion Fields

        #region Properties

        /// <summary>
        /// Gets the helper object.
        /// </summary>
        /// <value>
        /// The helper.
        /// </value>
        protected override AuthenticationHelper Helper
        {
            get
            {
                var authenticationHelper = helper;
                Assert.IsNotNull(authenticationHelper, "AuthenticationHelper has not been set. It must be set in Initialize.");
                return authenticationHelper;
            }
        }

        #endregion Properties

        #region MembershipAuthenticationProvider Overrides

        /// <summary>
        /// Initializes the provider.
        /// </summary>
        /// <param name="name">The friendly name of the provider.</param>
        /// <param name="config">A collection of the name/value pairs representing the provider-specific attributes specified in the configuration for this provider.</param>
        public override void Initialize(string name, NameValueCollection config)
        {
            Assert.ArgumentNotNullOrEmpty(name, "name");
            Assert.ArgumentNotNull(config, "config");

            base.Initialize(name, config);
            helper = new ClaimsAuthenticationHelper(this);
        }

        /// <summary>
        /// Gets the active user.
        /// </summary>
        /// <returns>
        /// Active User.
        /// </returns>
        public override User GetActiveUser()
        {
            var activeUser = Helper.GetActiveUser();
            Assert.IsNotNull(activeUser, "Active user cannot be empty.");
            return activeUser;
        }

        /// <summary>
        /// Logs the specified user into the system without checking password.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="persistent">If set to <c>true</c> (and the provider supports it), the login will be persisted.</param>
        /// <returns></returns>
        public override bool Login(string userName, bool persistent)
        {
            Assert.ArgumentNotNullOrEmpty(userName, "userName");
            return Login(User.FromName(userName, true));
        }

        /// <summary>
        /// Logs in the specified user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        public override bool Login(User user)
        {
            Assert.ArgumentNotNull(user, "user");
            return this.Login(user.Name, new List<Claim>());
        }

        public virtual bool Login(string userName, IEnumerable<Claim> claims)
        {
            Assert.ArgumentNotNullOrEmpty(userName, "userName");
            SessionSecurityToken sessionToken;
            if (!FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken))
            {
                // if current user is not claims principal create one from user instance

                var filteredClaims = claims.Where(c => (c.Type != ClaimTypes.Name || c.Type != ClaimTypes.NameIdentifier || c.Type != IdentityProvider));
                var claimsList = filteredClaims.ToList();
                claimsList.AddRange(new[]
                {
                    new Claim(ClaimTypes.Name, Globalize(Context.Domain.Name, userName)),
                    new Claim(ClaimTypes.NameIdentifier, Globalize(Context.Domain.Name,userName))
                });

                claimsList.Add(new Claim(IdentityProvider, claims.FirstOrDefault(c => c.Type == IdentityProvider || c.Type == "idp")?.Value ?? "Unknown"));

                var id = new ClaimsIdentity(claimsList, "Forms");
                var claimsPrincipal = new ClaimsPrincipal(id);

                var token = new SessionSecurityToken(claimsPrincipal);
                var sam = FederatedAuthentication.SessionAuthenticationModule;
                sam.WriteSessionTokenToCookie(token);
            }

            return true;
        }

        /// <summary>
        /// Logs out the current user.
        /// </summary>
        public override void Logout()
        {
            SessionSecurityToken sessionToken;
            if (!FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken))
            {
                // Clean up
            }
            base.Logout();
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
        }

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="user">The user object.</param>
        public override void SetActiveUser(User user)
        {
            Helper.SetActiveUser(user);
        }

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        public override void SetActiveUser(string userName)
        {
            Assert.ArgumentNotNullOrEmpty(userName, "userName");
            Helper.SetActiveUser(userName);
        }

        #endregion MembershipAuthenticationProvider Overrides

        #region Methods

        private static string Globalize(string domainName, string userName)
        {
            var str = userName;
            if (userName.Contains("\\"))
                return str;

            if (!userName.StartsWith(domainName + "\\"))
                str = domainName + "\\" + userName;
            return str;
        }

        #endregion Methods
    }
}