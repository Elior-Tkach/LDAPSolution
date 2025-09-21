using System;
using System.IO;
using System.Reflection;
using System.Linq;
using NLog;

namespace LDAP_DLL
{
    public class LDAP_Setup
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

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
        public static LdapResponse RecordLdapServerDetailsSimple(string host)
        {
            logger.Info($"RecordLdapServerDetailsSimple called with host: {host}");
            var response = new LdapResponse();
            try
            {
                // Get server details using PingServerSimple
                string pingInfo;
                bool pingSuccess = LDAP_Functions.PingServerSimple(host, out pingInfo);

                if (!pingSuccess)
                {
                    response.Success = false;
                    response.ErrorMessage = $"Failed to ping server: {pingInfo}";
                    logger.Warn(response.ErrorMessage);
                    return response;
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
                    logger.Info($"Created new INI file at {iniPath} with server details.");
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
                                logger.Info("Server details unchanged in INI file.");
                                return response;
                            }
                            else
                            {
                                // Update the line
                                lines[i] = newServerLine;
                                File.WriteAllLines(iniPath, lines);
                                logger.Info($"Updated server details in INI file at {iniPath}.");
                                return response;
                            }
                        }
                    }
                    // If we reach here, "Server:" line was not found, do nothing as per user request
                    logger.Info("No server line found in INI file; no changes made.");
                    return response;
                }
                return response;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                logger.Error(ex, $"RecordLdapServerDetailsSimple exception: {response.ErrorMessage}");
                return response;
            }
        }


        // Unified function to save (add or update) a user/group entry
        public static LdapResponse SaveLdapPermission(string name, string type, string permissionType)
        {
            logger.Info($"SaveLdapPermission called with name: {name}, type: {type}, permissionType: {permissionType}");
            var response = new LdapResponse();
            try
            {
                string iniPath = GetIniPath();
                if (!File.Exists(iniPath))
                {
                    response.Success = false;
                    response.ErrorMessage = "INI file does not exist.";
                    logger.Warn(response.ErrorMessage);
                    return response;
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
                        logger.Info($"Updated permission for {name} ({type}) to {permissionType} in INI file.");
                        break;
                    }
                }

                if (!found)
                {
                    // Append new entry
                    lines.Add($"{name},{type},{permissionType}");
                    logger.Info($"Added new permission entry for {name} ({type}) with permission {permissionType}.");
                }

                File.WriteAllLines(iniPath, lines);

                return response;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                logger.Error(ex, $"SaveLdapPermission exception: {response.ErrorMessage}");
                return response;
            }
        }

        // Clear all user and group entries, keeping only comments and the server details line
        public static LdapResponse ClearLdapPermissions()
        {
            logger.Info("ClearLdapPermissions called");
            var response = new LdapResponse();
            try
            {
                string iniPath = GetIniPath();
                if (!File.Exists(iniPath))
                {
                    response.Success = false;
                    response.ErrorMessage = "INI file does not exist.";
                    logger.Warn(response.ErrorMessage);
                    return response;
                }

                var lines = File.ReadAllLines(iniPath)
                    .Where(line => line.Trim().StartsWith("#") || string.IsNullOrWhiteSpace(line) || line.Trim().StartsWith("Server:"))
                    .ToList();

                File.WriteAllLines(iniPath, lines);

                logger.Info("Cleared all user and group permissions from INI file.");
                return response;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                logger.Error(ex, $"ClearLdapPermissions exception: {response.ErrorMessage}");
                return response;
            }
        }

        // LDAP passthrough functions
        public static LdapResponse GetUser(string ldapPath, string userName, string username, string password)
        {
            var response = new LdapResponse();
            string errorMessage;
            response.ResultString = LDAP_Functions.GetUserByUserNameSimple(ldapPath, out errorMessage, userName, username, password);
            if (!string.IsNullOrEmpty(errorMessage))
            {
                response.Success = false;
                response.ErrorMessage = errorMessage;
            }
            return response;
        }

        public static LdapResponse GetGroup(string ldapPath, string groupName, string username, string password)
        {
            var response = new LdapResponse();
            string errorMessage;
            response.ResultString = LDAP_Functions.GetGroupByNameSimple(ldapPath, out errorMessage, groupName, username, password);
            if (!string.IsNullOrEmpty(errorMessage))
            {
                response.Success = false;
                response.ErrorMessage = errorMessage;
            }
            return response;
        }

        public static LdapResponse GetAllGroups(string ldapPath, string username, string password)
        {
            var response = new LdapResponse();
            string errorMessage;
            response.ResultArray = LDAP_Functions.GetAllLdapGroupsArray(ldapPath, out errorMessage, username, password);
            if (!string.IsNullOrEmpty(errorMessage))
            {
                response.Success = false;
                response.ErrorMessage = errorMessage;
            }
            return response;
        }

        public static LdapResponse GetUsersInGroup(string ldapPath, string groupName, string username, string password)
        {
            var response = new LdapResponse();
            string errorMessage;
            response.ResultArray = LDAP_Functions.GetUsersInGroupArray(ldapPath, out errorMessage, groupName, username, password);
            if (!string.IsNullOrEmpty(errorMessage))
            {
                response.Success = false;
                response.ErrorMessage = errorMessage;
            }
            return response;
        }

        public static LdapResponse TestConnection(string host)
        {
            var response = new LdapResponse();
            string errorMessage;
            response.ResultBool = LDAP_Functions.PingServerSimple(host, out errorMessage);
            if (!response.ResultBool)
            {
                response.Success = false;
                response.ErrorMessage = errorMessage;
            }
            return response;
        }
    }
}
