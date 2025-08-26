using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;

public enum AuthStatus
{
    Success = 0,
    UserNotFound = 1,
    InvalidCredentials = 2,
    NoPermission = 3,
    LdapError = 4
}

public class AuthResult
{
    public AuthStatus Status { get; set; }
    public List<string> Groups { get; set; } = new List<string>();
}

public class UserTypeConfig
{
    public List<string> ExplicitUsers { get; set; } = new List<string>();
    public List<string> AllowedGroups { get; set; } = new List<string>();
}

public class LdapAuthenticator
{
    private readonly string _domain;

    public LdapAuthenticator(string domain)
    {
        _domain = domain;
    }

    /// <summary>
    /// Authenticates a user based on explicit user list and group membership for the given user type.
    /// </summary>
    /// <param name="username">User's LDAP username</param>
    /// <param name="password">User's LDAP password</param>
    /// <param name="userTypeConfig">Configuration for the selected user type</param>
    /// <returns>AuthResult with status and groups</returns>
    public AuthResult Authenticate(string username, string password, UserTypeConfig userTypeConfig)
    {
        var result = new AuthResult();

        try
        {
            using (var context = new PrincipalContext(ContextType.Domain, _domain))
            {
                // STEP 1: Check explicit user list
                if (userTypeConfig.ExplicitUsers.Contains(username, StringComparer.OrdinalIgnoreCase))
                {
                    if (context.ValidateCredentials(username, password))
                    {
                        // Fetch groups since authentication succeeded
                        result.Groups = GetUserGroups(context, username);
                        result.Status = AuthStatus.Success;
                        return result;
                    }
                    else
                    {
                        result.Status = AuthStatus.InvalidCredentials;
                        return result;
                    }
                }

                // STEP 2: User not in explicit list → authenticate first
                if (!context.ValidateCredentials(username, password))
                {
                    result.Status = AuthStatus.InvalidCredentials;
                    return result;
                }

                // Fetch groups
                result.Groups = GetUserGroups(context, username);

                // Check if any group matches allowed groups for this user type
                foreach (var group in result.Groups)
                {
                    if (userTypeConfig.AllowedGroups.Contains(group, StringComparer.OrdinalIgnoreCase))
                    {
                        result.Status = AuthStatus.Success;
                        return result;
                    }
                }

                result.Status = AuthStatus.NoPermission;
                return result;
            }
        }
        catch (Exception)
        {
            result.Status = AuthStatus.LdapError;
            return result;
        }
    }

    /// <summary>
    /// Gets all LDAP groups for the given username.
    /// </summary>
    private List<string> GetUserGroups(PrincipalContext context, string username)
    {
        var groups = new List<string>();
        var user = UserPrincipal.FindByIdentity(context, username);
        if (user != null)
        {
            foreach (var group in user.GetGroups())
            {
                groups.Add(group.SamAccountName);
            }
        }
        return groups;
    }
}
