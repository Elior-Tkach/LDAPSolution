using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Security.Authentication;

namespace LDAPConsoleTest
{
    public class LdapService : IDisposable
    {
        private readonly PrincipalContext _context;
        private readonly HashSet<string> _userGroups;
        private readonly HashSet<string> _adminGroups;

        public LdapService(string ldapUrl, IEnumerable<string> userGroupNames, IEnumerable<string> adminGroupNames)
        {
            if (string.IsNullOrWhiteSpace(ldapUrl)) throw new ArgumentException(nameof(ldapUrl));

            _userGroups = new HashSet<string>(userGroupNames ?? throw new ArgumentNullException(nameof(userGroupNames)), StringComparer.OrdinalIgnoreCase);

            _adminGroups = new HashSet<string>(adminGroupNames ?? throw new ArgumentNullException(nameof(adminGroupNames)), StringComparer.OrdinalIgnoreCase);


            // You can adjust ContextType.Domain or ContextType.ApplicationDirectory as needed

            _context = new PrincipalContext(ContextType.Domain, ldapUrl);
        }

        // ✅ Init function
        public (bool Valid, string Error) Init()
        {
            try
            {
                // Simple check if context can be used
                if (_context == null)
                {
                    return (false, "LDAP context not initialized.");
                }

                return (true, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        // ✅ Login function
        public AuthResult Login(string upn, string password)

        {

            if (string.IsNullOrWhiteSpace(upn)) throw new ArgumentException(nameof(upn));

            if (password == null) throw new ArgumentNullException(nameof(password));


            // 1. Validate credentials (simple bind)

            bool isValid = _context.ValidateCredentials(upn, password, ContextOptions.Negotiate);

            if (!isValid)

                throw new AuthenticationException("Invalid credentials or unable to bind to Active Directory.");


            // 2. Find the user principal to inspect group membership


            using (var user = UserPrincipal.FindByIdentity(_context, IdentityType.UserPrincipalName, upn))

            {

                if (user == null)

                    throw new AuthenticationException("User not found in Active Directory.");


                // fetch all groups the user is a member of

                var groups = user.GetAuthorizationGroups()

                .OfType<Principal>()

                .Select(g => g.SamAccountName)

                .Where(name => !string.IsNullOrEmpty(name))

                .ToHashSet(StringComparer.OrdinalIgnoreCase);


                // check membership

                bool isAdmin = groups.Overlaps(_adminGroups);

                bool isUser = groups.Overlaps(_userGroups);


                return new AuthResult

                {

                    IsAuthenticated = true,

                    IsAdmin = isAdmin,

                    IsUser = isUser

                };

            }

        }

        // ✅ Request function (for Inactivity Timeout or Min Password Length)
        public string Request(string type)
        {
            // Placeholder: You will implement DirectorySearcher here later
            if (type == "InactivityTimeout")
            {
                return "30"; // minutes (stub for now)
            }
            if (type == "MinPasswordLength")
            {
                return "8"; // stub
            }

            throw new ArgumentException("Unsupported type");
        }

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}
