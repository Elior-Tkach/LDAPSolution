using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.IO;

namespace LDAP_DLL
{
    internal class Authentication
    {
        public static bool AuthenticateUser(string ldapPath, string username, string password, out string errorMessage)
        {
            errorMessage = string.Empty;
            try
            {
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                {
                    // Force authentication by accessing NativeObject
                    var obj = entry.NativeObject;
                }
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }

        public static bool IsUserRegistered(string userName, string expectedPermissionType, out string errorMessage)
        {
            errorMessage = null;
            try
            {
                string iniPath = Setup.GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
                    return false;
                }
                var lines = File.ReadAllLines(iniPath);
                foreach (var line in lines)
                {
                    if (line.StartsWith("#") || line.StartsWith("Name,")) continue;
                    var parts = line.Split(',');
                    if (parts.Length >= 4 && parts[0] == userName && parts[1] == "User")
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


        public static bool IsUserInRegisteredGroup(string ldapPath, string userName, string username, string password, string permissionType, out string errorMessage)
        {
            errorMessage = null;
            try
            {
                var userGroups = LDAP_Functions.GetGroupsForUserArray(ldapPath, out errorMessage, userName, username, password);
                if (userGroups == null || userGroups.Length == 0)
                {
                    if (string.IsNullOrEmpty(errorMessage))
                        errorMessage = "User does not belong to any groups or failed to retrieve groups.";
                    return false;
                }
                string iniPath = Setup.GetIniPath();
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
                        if (line.StartsWith("#") || line.StartsWith("Name,")) continue;
                        var parts = line.Split(',');
                        if (parts.Length >= 4 && parts[0] == group && parts[1] == "Group")
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
