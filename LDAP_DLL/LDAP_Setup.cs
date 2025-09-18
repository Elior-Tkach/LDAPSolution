using System;
using System.IO;
using System.Reflection;
using System.Linq;

namespace LDAP_DLL
{
    public class LDAP_Setup
    {

        internal LDAP_Setup()
        {
        }


        // Helper to get the INI file path
        internal static string GetIniPath()
        {
            var dllPath = Assembly.GetExecutingAssembly().Location;
            var dir = Path.GetDirectoryName(dllPath);
            return Path.Combine(dir, "LDAP.ini");
        }

        // Writes server data as the header if not present
        public static bool RecordLdapServerDetailsSimple(string host, out string errorMessage)
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
                string newServerLine = $"Server: IPs={ips}, HostName={hostName}";
                if (!File.Exists(iniPath))
                {
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("# ======================================================");
                    sb.AppendLine("# LDAP Configuration File");
                    sb.AppendLine("# ======================================================");
                    sb.AppendLine();
                    sb.AppendLine("# --------- Server Information ---------");
                    sb.AppendLine(newServerLine);
                    sb.AppendLine();
                    sb.AppendLine("# --------- Access Control List ---------");
                    sb.AppendLine("# Columns: name,type,permission");
                    sb.AppendLine("# type: U= user, G= group");
                    sb.AppendLine("# permission: A = Admin, O = Operator");
                    File.WriteAllText(iniPath, sb.ToString());
                }
                else
                {
                    var lines = File.ReadAllLines(iniPath).ToList();
                    for (int i = 0; i < lines.Count; i++)
                    {
                        if (lines[i].StartsWith("Server:"))
                        {
                            if (lines[i].Trim() == newServerLine)
                            {
                                // Details are the same, do nothing
                                errorMessage = null;
                                return true;
                            }
                            else
                            {
                                // Update the line
                                lines[i] = newServerLine;
                                File.WriteAllLines(iniPath, lines);
                                errorMessage = null;
                                return true;
                            }
                        }
                    }
                    // If we reach here, "Server:" line was not found, do nothing as per user request
                    errorMessage = null;
                    return true;
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


        // Unified function to save (add or update) a user/group entry
        public static bool SaveLdapPermission(string name, string type, string permissionType, out string errorMessage)
        {
            try
            {
                string iniPath = GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
                    return false;
                }

                var lines = File.ReadAllLines(iniPath).ToList();
                bool found = false;

                for (int i = 0; i < lines.Count; i++)
                {
                    var line = lines[i];
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;

                    var parts = line.Split(',');
                    if (parts.Length >= 3 && parts[0] == name && parts[1] == type)
                    {
                        // Update existing entry
                        parts[2] = permissionType;
                        lines[i] = string.Join(",", parts);
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    // Append new entry
                    lines.Add($"{name},{type},{permissionType}");
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

        // Clear all user and group entries, keeping only comments and the server details line
        public static bool ClearLdapPermissions(out string errorMessage)
        {
            try
            {
                string iniPath = GetIniPath();
                if (!File.Exists(iniPath))
                {
                    errorMessage = "INI file does not exist.";
                    return false;
                }

                var lines = File.ReadAllLines(iniPath)
                    .Where(line => line.Trim().StartsWith("#") || string.IsNullOrWhiteSpace(line) || line.Trim().StartsWith("Server:"))
                    .ToList();

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

        // LDAP passthrough functions
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
