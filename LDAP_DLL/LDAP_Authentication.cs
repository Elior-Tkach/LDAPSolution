using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.IO;

namespace LDAP_DLL
{
    public class LDAP_Authentication
    {

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
                    return true;
                }
                // Check group permission
                if (IsUserInRegisteredGroup(username, username, password, permissionType, out errorMessage))
                {
                    return true;
                }
                // If neither, return false
                if (string.IsNullOrEmpty(errorMessage))
                    errorMessage = "User does not have the required permission type.";
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }

        internal static bool IsUserRegistered(string userName, string expectedPermissionType, out string errorMessage)
        {
            errorMessage = null;
            try
            {
                string iniPath = LDAP_Setup.GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
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
                            return true;
                        }
                        else
                        {
                            errorMessage = $"User found, but permission type does not match. Expected: {expectedPermissionType}, Found: {parts[2]}";
                            return false;
                        }
                    }
                }
                errorMessage = "User not found in INI file.";
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }

        internal static bool IsUserInRegisteredGroup(string userName, string username, string password, string permissionType, out string errorMessage)
        {
            errorMessage = null;
            try
            {
                string ldapPath = GetLdapPathFromIni();
                var userGroups = LDAP_Functions.GetGroupsForUserArray(ldapPath, out errorMessage, userName, username, password);
                if (userGroups == null || userGroups.Length == 0)
                {
                    if (string.IsNullOrEmpty(errorMessage))
                        errorMessage = "User does not belong to any groups or failed to retrieve groups.";
                    return false;
                }
                string iniPath = LDAP_Setup.GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
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
                                return true;
                            }
                        }
                    }
                }
                errorMessage = $"No registered group found for user in INI file with permission type '{permissionType}'.";
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }
    }
}
