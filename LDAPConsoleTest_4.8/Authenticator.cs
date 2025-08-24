using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

public class Authenticator
{
    // Define constants for return codes
    private const int SUCCESS = 0;
    private const int USER_NOT_FOUND = 1;
    private const int NO_PERMISSION = 2;
    private const int LDAP_ERROR = 3;

    // Application allowed groups
    private static readonly HashSet<string> AllowedGroups = new HashSet<string>
    {
        "AppAdmins",
        "AppUsers"
    };

    /// <summary>
    /// Authenticates a user against LDAP and checks group membership.
    /// </summary>
    /// <param name="username">User's LDAP username</param>
    /// <param name="password">User's LDAP password</param>
    /// <param name="userGroups">A list to store user's groups if authentication succeeds</param>
    /// <returns>0 if success, otherwise error code</returns>
    public static int AuthenticateUser(string username, string password, ref List<string> userGroups)
    {
        try
        {
            // Configure the domain context (change domain and container as needed)
            using (PrincipalContext context = new PrincipalContext(ContextType.Domain, "YOUR_DOMAIN"))
            {
                // Validate user credentials
                bool isValid = context.ValidateCredentials(username, password);
                if (!isValid)
                {
                    return USER_NOT_FOUND;
                }

                // Get the user principal
                UserPrincipal user = UserPrincipal.FindByIdentity(context, username);
                if (user == null)
                {
                    return USER_NOT_FOUND;
                }

                // Fetch groups
                userGroups = new List<string>();
                foreach (GroupPrincipal group in user.GetGroups())
                {
                    userGroups.Add(group.SamAccountName);
                }

                // Check for allowed group
                foreach (string groupName in userGroups)
                {
                    if (AllowedGroups.Contains(groupName))
                    {
                        return SUCCESS;
                    }
                }

                return NO_PERMISSION; // User authenticated but has no permission
            }
        }
        catch (Exception)
        {
            return LDAP_ERROR; // Some LDAP or connection error occurred
        }
    }
}
