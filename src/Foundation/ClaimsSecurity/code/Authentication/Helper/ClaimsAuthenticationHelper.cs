/*
 --------------------------------------------------------------
 ***** Source code taken from *****
 http://webcmd.wordpress.com/2012/07/09/federated-authentication-with-sitecore-and-the-windows-identity-foundation/
 --------------------------------------------------------------
 */

using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Principal;
using System.Threading;
using System.Web;
using Sitecore.Diagnostics;
using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;

namespace Sitecore.Foundation.ClaimsSecurity.Authentication.Helper
{
    using System.Security.Claims;

    public class ClaimsAuthenticationHelper : AuthenticationHelper
    {
        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="ClaimsAuthenticationHelper"/> class.
        /// </summary>
        /// <param name="provider">The provider.</param>
        public ClaimsAuthenticationHelper(AuthenticationProvider provider)
            : base(provider)
        {
        }

        #endregion Constructor

        #region AuthenticationHelper Overrides

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="user">The user object.</param>
        public override void SetActiveUser(User user)
        {
            Assert.ArgumentNotNull(user, "user");

            base.SetActiveUser(user);
        }

        /// <summary>
        /// Sets the active user.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        public override void SetActiveUser(string userName)
        {
            Assert.ArgumentNotNull(userName, "userName");

            base.SetActiveUser(userName);
        }

        #endregion AuthenticationHelper Overrides

        #region Methods

        /// <summary>
        /// Determines whether the specified user is disabled.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        protected virtual bool IsDisabled(User user)
        {
            Assert.ArgumentNotNull(user, "user");

            return !user.Profile.IsAnonymous && user.Profile.State.Contains("Disabled");
        }

        /// <summary>
        /// Gets the current user.
        /// </summary>
        /// <returns>
        /// The current user; <c>null</c> if user is not defined (anonymous).
        /// </returns>
        protected override User GetCurrentUser()
        {
            var current = HttpContext.Current;
            if (current == null)
            {
                if (Thread.CurrentPrincipal != null)
                {
                    if (Thread.CurrentPrincipal is User)
                    {
                        return Thread.CurrentPrincipal as User;
                    }
                    if (!string.IsNullOrEmpty(Thread.CurrentPrincipal.Identity.Name))
                    {
                        return GetUser(Thread.CurrentPrincipal.Identity);
                    }
                }

                return null;
            }

            var user = HttpContext.Current.User;
            if (user != null)
            {
                if (user is User)
                {
                    return user as User;
                }

                var identity = user.Identity;
                return string.IsNullOrEmpty(identity.Name) ? null : GetUser(identity);
            }

            SessionSecurityToken sessionToken;
            FederatedAuthentication.SessionAuthenticationModule.TryReadSessionTokenFromCookie(out sessionToken);

            if (sessionToken?.ClaimsPrincipal != null)
            {
                var identity = sessionToken.ClaimsPrincipal.Identity;
                if (!string.IsNullOrEmpty(identity.Name))
                    return GetUser(sessionToken.ClaimsPrincipal);
            }

            return base.GetCurrentUser();
        }

        private static User GetUser(IPrincipal principal)
        {
            Assert.ArgumentNotNull(principal, "principal");

            return User.FromPrincipal(principal);
        }

        /// <summary>
        /// Gets the user.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <returns></returns>
        private static User GetUser(IIdentity identity)
        {
            Assert.ArgumentNotNull(identity, "identity");

            return User.FromPrincipal(new ClaimsPrincipal(identity));
        }

        private new static User GetUser(string userName, bool isAuthenticated)
        {
            Assert.ArgumentNotNull(userName, "userName");

            return User.FromName(userName, isAuthenticated);
        }

        #endregion Methods
    }
}