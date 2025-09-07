using System;
using System.IO;
using System.Reflection;


namespace LDAP_DLL
{
    internal class Setup
    {
        // Helper to get the INI file path
        internal static string GetIniPath()
        {
            var dllPath = Assembly.GetExecutingAssembly().Location;
            var dir = Path.GetDirectoryName(dllPath);
            return Path.Combine(dir, "LDAP.ini");
        }

        // Writes server data as the header if not present
        internal static bool RecordLdapServerDetailsSimple(string host, string username, out string errorMessage)
        {
            try
            {
                // Get server details using PingServerSimple
                string pingInfo;
                bool pingSuccess = LDAP_Functions.PingServerSimple(host, out pingInfo);

                if (!pingSuccess)
                {
                    errorMessage = $"Failed to ping server: {pingInfo}";
                    return false;
                }

                // Parse pingInfo for IPs and HostName
                // Example: "Ping succeeded. IPs: 192.168.1.10, fe80::1, HostName: myserver.domain.com"
                string ips = "N/A";
                string hostName = "N/A";
                var ipIndex = pingInfo.IndexOf("IPs:");
                var hostIndex = pingInfo.IndexOf("HostName:");
                if (ipIndex >= 0 && hostIndex > ipIndex)
                {
                    ips = pingInfo.Substring(ipIndex + 4, hostIndex - (ipIndex + 4)).Trim(' ', ',');
                    hostName = pingInfo.Substring(hostIndex + 9).Trim();
                }

                string iniPath = GetIniPath();
                if (!File.Exists(iniPath))
                {
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("# ======================================================");
                    sb.AppendLine("# LDAP Configuration File");
                    sb.AppendLine("# ======================================================");
                    sb.AppendLine();
                    sb.AppendLine("# --------- Server Information ---------");
                    sb.AppendLine($"Server: IPs={ips}, HostMame={hostName}");
                    sb.AppendLine();
                    sb.AppendLine("# --------- Access Control List ---------");
                    sb.AppendLine("# Columns: name,type,permission");
                    sb.AppendLine("# type: U= user, G= group");
                    sb.AppendLine("# permission: A = Admin, O = Operator");
                    File.WriteAllText(iniPath, sb.ToString());
                }
                errorMessage = null;
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }

        // Appends a user or group entry
        internal static bool RecordLdapUserDetailsSimple(string userName, string displayName, string email, out string errorMessage)
        {
            return RecordLdapEntry(userName, "User", "O", out errorMessage); // Default permissionType 'O', adjust as needed
        }

        internal static bool RecordLdapGroupDetailsSimple(string groupName, string description, out string errorMessage)
        {
            return RecordLdapEntry(groupName, "Group", "O", out errorMessage); // Default permissionType 'O', adjust as needed
        }

        internal static bool RecordLdapEntry(string name, string type, string permissionType, out string errorMessage)
        {
            try
            {
                string iniPath = GetIniPath();
                string entry = $"{name},{type},{permissionType},{DateTime.Now:yyyy-MM-dd HH:mm:ss}{Environment.NewLine}";
                File.AppendAllText(iniPath, entry);
                errorMessage = null;
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }

        public static bool MarkUserPermission(string userName, string permissionType, out string errorMessage)
        {
            return MarkPermission(userName, "User", permissionType, out errorMessage);
        }

        public static bool MarkGroupPermission(string groupName, string permissionType, out string errorMessage)
        {
            return MarkPermission(groupName, "Group", permissionType, out errorMessage);
        }

        // Helper to update permission type for user or group
        private static bool MarkPermission(string name, string type, string permissionType, out string errorMessage)
        {
            try
            {
                string iniPath = GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
                    return false;
                }
                var lines = File.ReadAllLines(iniPath);
                bool found = false;
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    if (line.StartsWith("#") || line.StartsWith("Name,")) continue;
                    var parts = line.Split(',');
                    if (parts.Length >= 4 && parts[0] == name && parts[1] == type)
                    {
                        parts[2] = permissionType;
                        lines[i] = string.Join(",", parts);
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    errorMessage = $"{type} '{name}' not found in INI file.";
                    return false;
                }
                File.WriteAllLines(iniPath, lines);
                errorMessage = null;
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }

        public static string GetUser(string ldapPath, out string errorMessage, string userName, string username, string password)
        {
            return LDAP_Functions.GetUserByUserNameSimple(ldapPath, out errorMessage, userName, username, password);
        }

        public static string GetGroup(string ldapPath, out string errorMessage, string groupName, string username, string password)
        {
            return LDAP_Functions.GetGroupByNameSimple(ldapPath, out errorMessage, groupName, username, password);
        }

        public static string[] GetAllGroups(string ldapPath, out string errorMessage, string username, string password)
        {
            return LDAP_Functions.GetAllLdapGroupsArray(ldapPath, out errorMessage, username, password);
        }

        public static string[] GetUsersInGroup(string ldapPath, out string errorMessage, string groupName, string username, string password)
        {
            return LDAP_Functions.GetUsersInGroupArray(ldapPath, out errorMessage, groupName, username, password);
        }

        public static bool TestConnection(string host, out string errorMessage)
        {
            return LDAP_Functions.PingServerSimple(host, out errorMessage);
        }
    }
}
