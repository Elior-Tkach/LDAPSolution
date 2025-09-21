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
                throw new FileNotFoundException("INI file does not exist.");
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
            throw new InvalidOperationException("LDAP IP not found in INI file header.");
        }

        public static bool AuthenticateUser(string username, string password, string permissionType, out string errorMessage)
        {
            logger.Info($"AuthenticateUser called with username: {username}, permissionType: {permissionType}");
            errorMessage = string.Empty;
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
                if (IsUserRegistered(username, permissionType, out errorMessage))
                {
                    logger.Info($"User '{username}' authenticated and registered with permission '{permissionType}'.");
                    return true;
                }
                // Check group permission
                if (IsUserInRegisteredGroup(username, username, password, permissionType, out errorMessage))
                {
                    logger.Info($"User '{username}' authenticated via group with permission '{permissionType}'.");
                    return true;
                }
                // If neither, return false
                if (string.IsNullOrEmpty(errorMessage))
                    errorMessage = "User does not have the required permission type.";
                logger.Warn($"Authentication failed for user '{username}': {errorMessage}");
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                logger.Error(ex, $"AuthenticateUser exception for user '{username}': {errorMessage}");
                return false;
            }
        }

        internal static bool IsUserRegistered(string userName, string expectedPermissionType, out string errorMessage)
        {
            logger.Info($"IsUserRegistered called with userName: {userName}, expectedPermissionType: {expectedPermissionType}");
            errorMessage = null;
            try
            {
                string iniPath = LDAP_Setup.GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
                    logger.Warn(errorMessage);
                    return false;
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
                            errorMessage = $"User found, but permission type does not match. Expected: {expectedPermissionType}, Found: {parts[2]}";
                            logger.Warn(errorMessage);
                            return false;
                        }
                    }
                }
                errorMessage = "User not found in INI file.";
                logger.Warn(errorMessage);
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                logger.Error(ex, $"IsUserRegistered exception for user '{userName}': {errorMessage}");
                return false;
            }
        }

        internal static bool IsUserInRegisteredGroup(string userName, string username, string password, string permissionType, out string errorMessage)
        {
            logger.Info($"IsUserInRegisteredGroup called with userName: {userName}, permissionType: {permissionType}");
            errorMessage = null;
            try
            {
                string ldapPath = GetLdapPathFromIni();
                var userGroups = LDAP_Functions.GetGroupsForUserArray(ldapPath, out errorMessage, userName, username, password);
                if (userGroups == null || userGroups.Length == 0)
                {
                    if (string.IsNullOrEmpty(errorMessage))
                        errorMessage = "User does not belong to any groups or failed to retrieve groups.";
                    logger.Warn($"User '{userName}' group check failed: {errorMessage}");
                    return false;
                }
                string iniPath = LDAP_Setup.GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
                    logger.Warn(errorMessage);
                    return false;
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
                        }
                    }
                }
                errorMessage = $"No registered group found for user in INI file with permission type '{permissionType}'.";
                logger.Warn(errorMessage);
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                logger.Error(ex, $"IsUserInRegisteredGroup exception for user '{userName}': {errorMessage}");
                return false;
            }
        }
    }
}
