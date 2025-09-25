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

        // Helper to get LDAP path (host) from INI file header
        private static string GetLdapPathFromIni()
        {
            string iniPath = LDAP_Setup.GetIniPath();
            if (!File.Exists(iniPath))
                throw new LdapIniFileNotFoundException();
            var lines = File.ReadAllLines(iniPath);
            foreach (var line in lines)
            {
                if (line.StartsWith("Server: IPs="))
                {
                    var IPPart = line.Split(',')[0];
                    var IPEq = IPPart.IndexOf("IPs=");
                    if (IPEq >= 0)
                    {
                        return IPPart.Substring(IPEq + 4).Trim();
                    }
                }
            }
            throw new LdapIpNotFoundException();
        }

        internal static bool IsUserRegistered(string userName, string expectedPermissionType)
        {
            logger.Info($"IsUserRegistered called with userName: {userName}, expectedPermissionType: {expectedPermissionType}");
            string iniPath = LDAP_Setup.GetIniPath();
            if (!File.Exists(iniPath))
            {
                throw new LdapIniFileNotFoundException();
            }
            var lines = File.ReadAllLines(iniPath);
            foreach (var line in lines)
            {
                if (line.StartsWith("#") || line.StartsWith("Server:")) continue;
                var parts = line.Split(',');
                if (parts.Length >= 3 && parts[0] == userName && parts[1] == "U")
                {
                    if (string.Equals(parts[2], expectedPermissionType, StringComparison.OrdinalIgnoreCase))
                    {
                        logger.Info($"User '{userName}' found with matching permission '{expectedPermissionType}'.");
                        return true;
                    }
                    else
                    {
                        throw new LdapPermissionMismatchException(expectedPermissionType, parts[2]);
                    }
                }
            }
            throw new LdapUserNotFoundException(userName);
        }

        internal static bool IsUserInRegisteredGroup(string userName, string username, string password, string permissionType)
        {
            logger.Info($"IsUserInRegisteredGroup called with userName: {userName}, permissionType: {permissionType}");
            string ldapPath = GetLdapPathFromIni();
            string[] userGroups;
            try
            {
                userGroups = LDAP_Functions.GetGroupsForUserArray(ldapPath, userName, username, password);
            }
            catch (LdapFunctionsException ex)
            {
                logger.Warn($"Failed to get groups for user '{userName}': {ex.Message}");
                throw new LdapUserNotInGroupException(userName);
            }
            if (userGroups == null || userGroups.Length == 0)
            {
                throw new LdapUserNotInGroupException(userName);
            }
            string iniPath = LDAP_Setup.GetIniPath();
            if (!File.Exists(iniPath))
            {
                throw new LdapIniFileNotFoundException();
            }
            var lines = File.ReadAllLines(iniPath);
            foreach (var group in userGroups)
            {
                foreach (var line in lines)
                {
                    if (line.StartsWith("#") || line.StartsWith("Server:")) continue;
                    var parts = line.Split(',');
                    if (parts.Length >= 3 && parts[0] == group && parts[1] == "G")
                    {
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

        public static LdapResponse AuthenticateUser(string username, string password, string permissionType)
        {
            logger.Info($"AuthenticateUser called with username: {username}, permissionType: {permissionType}");
            var response = new LdapResponse();
            try
            {
                string ldapPath = GetLdapPathFromIni();
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                {
                    // Force authentication by accessing NativeObject
                    var obj = entry.NativeObject;
                }
                // Check user permission
                try
                {
                    if (IsUserRegistered(username, permissionType))
                    {
                        logger.Info($"User '{username}' authenticated and registered with permission '{permissionType}'.");
                        response.ResultBool = true;
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
                            response.ResultBool = true;
                            return response;
                        }
                    }
                    catch (LdapUserNotInGroupException gex)
                    {
                        // Set error number for group not found
                        response.Success = false;
                        response.ErrorMessage = gex.Message;
                        response.ErrorNumber = gex.ErrorNumber;
                        response.ResultBool = false;
                        return response;
                    }
                    catch (LdapAuthenticationException gex)
                    {
                        response.Success = false;
                        response.ErrorMessage = gex.Message;
                        response.ErrorNumber = gex.ErrorNumber;
                        response.ResultBool = false;
                        return response;
                    }
                    catch (Exception ex2)
                    {
                        logger.Error(ex2, $"Unexpected error while checking group registration for user '{username}': {ex2.Message}");
                        response.Success = false;
                        response.ErrorMessage = ex2.Message;
                        response.ErrorNumber = 4999;
                        response.ResultBool = false;
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
                response.ResultBool = false;
                return response;
            }
            catch (LdapAuthenticationException ex)
            {
                logger.Error(ex, $"Authentication exception for user '{username}': {ex.Message}");
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
                response.ResultBool = false;
                return response;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"AuthenticateUser exception for user '{username}': {ex.Message}");
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = 4020;
                response.ResultBool = false;
                return response;
            }
            return response;
        }
    }
}
