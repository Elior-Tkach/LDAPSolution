using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.IO;
using NLog;

namespace LDAP_DLL
{
    public class LDAP_Authentication
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        internal LDAP_Authentication()
        {
        }

        /// <summary>
        /// Helper to get LDAP path (host) from INI file header.
        /// </summary>
        /// <returns>The LDAP path as a string.</returns>
        // Helper to get LDAP path (host) from INI file header
        private static string GetLdapPathFromIni()
        {
            // Get the path to the INI file
            string iniPath = LDAP_Setup.GetIniPath();
            if (!File.Exists(iniPath))
                throw new LdapIniFileNotFoundException();
            // Read all lines from the INI file
            var lines = File.ReadAllLines(iniPath);
            foreach (var line in lines)
            {
                // Look for the server line with IP
                if (line.StartsWith("Server: IP="))
                {
                    var IPPart = line.Split(',')[0];
                    var IPEq = IPPart.IndexOf("IP=");
                    if (IPEq >=0)
                    {
                        // Return the IP value from the server line
                        return IPPart.Substring(IPEq +4).Trim();
                    }
                }
            }
            throw new LdapIpNotFoundException();
        }

        /// <summary>
        /// Checks if a user is registered in the INI file with the expected permission type.
        /// </summary>
        /// <param name="userName">The user name to check.</param>
        /// <param name="expectedPermissionType">The expected permission type (e.g., "A" or "O").</param>
        /// <returns>True if the user is registered with the expected permission; otherwise, throws an exception.</returns>
        internal static bool IsUserRegistered(string userName, string expectedPermissionType)
        {
            logger.Info($"IsUserRegistered called with userName: {userName}, expectedPermissionType: {expectedPermissionType}");
            // Get the path to the INI file
            string iniPath = LDAP_Setup.GetIniPath();
            if (!File.Exists(iniPath))
            {
                throw new LdapIniFileNotFoundException();
            }
            // Read all lines from the INI file
            var lines = File.ReadAllLines(iniPath);
            bool userFound = false;
            foreach (var line in lines)
            {
                // Skip comments and server info
                if (line.StartsWith("#") || line.StartsWith("Server:")) continue;
                var parts = line.Split(',');
                // Check if the line matches the user and type
                if (parts.Length >=3 && parts[0] == userName && parts[1] == "U")
                {
                    // Check if the permission matches
                    if (string.Equals(parts[2], expectedPermissionType, StringComparison.OrdinalIgnoreCase))
                    {
                        logger.Info($"User '{userName}' found with matching permission '{expectedPermissionType}'.");
                        return true;
                    }
                    else
                    {
                        userFound = true;
                    }
                }
            }
            if (userFound)
            {
                throw new LdapPermissionMismatchException(expectedPermissionType, "other");
            }
            throw new LdapUserNotFoundException(userName);
        }

        /// <summary>
        /// Checks if a user is in a registered group with the specified permission type.
        /// </summary>
        /// <param name="userName">The user name to check.</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <param name="permissionType">The required permission type (e.g., "A" or "O").</param>
        /// <returns>True if the user is in a group with the required permission; otherwise, throws an exception.</returns>
        internal static bool IsUserInRegisteredGroup(string userName, string username, string password, string permissionType)
        {
            logger.Info($"IsUserInRegisteredGroup called with userName: {userName}, permissionType: {permissionType}");
            // Get the LDAP path from the INI file
            string ldapPath = GetLdapPathFromIni();
            string[] userGroups;
            try
            {
                // Get all groups for the user from LDAP
                userGroups = LDAP_Functions.GetGroupsForUserArray(ldapPath, userName, username, password);
            }
            catch (LdapFunctionsException ex)
            {
                logger.Warn($"Failed to get groups for user '{userName}': {ex.Message}");
                throw new LdapUserNotInGroupException(userName);
            }
            if (userGroups == null || userGroups.Length ==0)
            {
                throw new LdapUserNotInGroupException(userName);
            }
            // Get the path to the INI file
            string iniPath = LDAP_Setup.GetIniPath();
            if (!File.Exists(iniPath))
            {
                throw new LdapIniFileNotFoundException();
            }
            // Read all lines from the INI file
            var lines = File.ReadAllLines(iniPath);
            foreach (var group in userGroups)
            {
                foreach (var line in lines)
                {
                    // Skip comments and server info
                    if (line.StartsWith("#") || line.StartsWith("Server:")) continue;
                    var parts = line.Split(',');
                    // Check if the line matches the group and type
                    if (parts.Length >=3 && parts[0] == group && parts[1] == "G")
                    {
                        // Check if the permission matches
                        if (string.Equals(parts[2], permissionType, StringComparison.OrdinalIgnoreCase))
                        {
                            logger.Info($"User '{userName}' is in group '{group}' with permission '{permissionType}'.");
                            return true;
                        }
                        else
                        {
                            logger.Info($"Group '{group}' found for user '{userName}', but permission type does not match. Expected: {permissionType}, Found: {parts[2]}");
                            throw new LdapPermissionMismatchException(permissionType, parts[2]);
                        }
                    }
                }
            }
            throw new LdapNoRegisteredGroupException(permissionType);
        }

        /// <summary>
        /// Authenticates a user against LDAP and checks for the required permission, either directly or via group membership.
        /// </summary>
        /// <param name="username">The username to authenticate.</param>
        /// <param name="password">The password for authentication.</param>
        /// <param name="permissionType">The required permission type (e.g., "A" or "O").</param>
        /// <returns>A LdapResponse object indicating the result of the authentication and permission check.</returns>
        public static LdapResponse AuthenticateUser(string username, string password, string permissionType)
        {
            logger.Info($"AuthenticateUser called with username: {username}, permissionType: {permissionType}");
            var response = new LdapResponse();
            try
            {
                // Get the LDAP path from the INI file
                string ldapPath = GetLdapPathFromIni();
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                // Try to bind to LDAP with the provided credentials
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                {
                    // Force authentication by accessing NativeObject
                    var obj = entry.NativeObject;
                }
                // Check if the user is registered directly
                try
                {
                    if (IsUserRegistered(username, permissionType))
                    {
                        logger.Info($"User '{username}' authenticated and registered with permission '{permissionType}'.");
                        response.Success = true;
                        logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                        return response;
                    }
                }
                catch (LdapAuthenticationException ex)
                {
                    // If not user, try group
                    logger.Warn($"User permission check failed: {ex.Message}");
                    // Only try group if user not found or permission mismatch
                    try
                    {
                        if (IsUserInRegisteredGroup(username, username, password, permissionType))
                        {
                            logger.Info($"User '{username}' authenticated via group with permission '{permissionType}'.");
                            response.Success = true;
                            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                            return response;
                        }
                    }
                    catch (LdapAuthenticationException gex)
                    {
                        // If the original exception is permission mismatch (4001), return its message and error number
                        if (ex.ErrorNumber ==4001)
                        {
                            response.Success = false;
                            response.ErrorMessage = ex.Message;
                            response.ErrorNumber = ex.ErrorNumber;
                            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                        }
                        else
                        {
                            response.Success = false;
                            response.ErrorMessage = gex.Message;
                            response.ErrorNumber = gex.ErrorNumber;
                        }
                        logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{{{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}}}]");
                        return response;
                    }
                    catch (Exception ex2)
                    {
                        logger.Error(ex2, $"Unexpected error while checking group registration for user '{username}': {ex2.Message}");
                        response.Success = false;
                        response.ErrorMessage = ex2.Message;
                        response.ErrorNumber =4020;
                        logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                        return response;
                    }
                }
            }
            catch (LdapSetupException ex)
            {
                logger.Error(ex, $"Setup exception for user '{username}': {ex.Message}");
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
            catch (LdapAuthenticationException ex)
            {
                logger.Error(ex, $"Authentication exception for user '{username}': {ex.Message}");
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"AuthenticateUser exception for user '{username}': {ex.Message}");
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber =4020;
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }
    }
}
