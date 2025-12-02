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


        /// <summary>
        /// Helper to get the INI file path for LDAP configuration.
        /// </summary>
        /// <returns>The full path to the LDAP.ini file.</returns>
        // Helper to get the INI file path
        internal static string GetIniPath()
        {
            // Get the path of the currently executing assembly (DLL)
            var dllPath = Assembly.GetExecutingAssembly().Location;
            // Get the directory containing the DLL
            var dir = Path.GetDirectoryName(dllPath);
            // Return the full path to LDAP.ini in the same directory
            return Path.Combine(dir, "LDAP.ini");
        }

        /// <summary>
        /// Writes or updates the server data as the header in the INI file if not present.
        /// </summary>
        /// <param name="host">The host name or IP address of the LDAP server.</param>
        /// <returns>A LdapResponse indicating the result of the operation.</returns>
        // Writes server data as the header if not present
        public static LdapResponse RecordLdapServerDetailsSimple(string host)
        {
            logger.Info($"RecordLdapServerDetailsSimple called with host: {host}");
            var response = new LdapResponse();
            try
            {
                string ips = "N/A";
                string hostName = "N/A";
                try
                {
                    // Resolve the host to get its host name and IPv4 addresses
                    var hostEntry = System.Net.Dns.GetHostEntry(host);
                    hostName = hostEntry.HostName;

                    var allAddresses = hostEntry.AddressList.Select(a => a.ToString()).ToArray();
                    logger.Info("All resolved addresses: " + string.Join(", ", allAddresses));

                    // Only include IPv4 addresses
                    var ipv4Addresses = hostEntry.AddressList
                        .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(a => a.ToString())
                        .ToArray();
                    if (ipv4Addresses.Length >0)
                    {
                        ips = string.Join(", ", ipv4Addresses);
                    }
                    else
                    {
                        logger.Warn("No IPv4 addresses resolved for host, using original host string in INI file.");
                        ips = host; // fallback to original host string
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Dns.GetHostEntry failed, using original host string in INI file. Exception: " + ex.Message);
                    ips = host; // fallback to original host string
                    hostName = host;
                }

                string iniPath = GetIniPath();
                string newServerLine = $"Server: IP= {ips}, HostName={hostName}";
                if (!File.Exists(iniPath))
                {
                    // Create a new INI file with server details and headers
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
                    try
                    {
                        File.WriteAllText(iniPath, sb.ToString());
                    }
                    catch (Exception ex)
                    {
                        throw new LdapIniFileWriteException(ex.Message);
                    }
                    logger.Info($"Created new INI file at {iniPath} with server details.");
                }
                else
                {
                    // Update the server line if it exists, otherwise do nothing
                    var lines = File.ReadAllLines(iniPath).ToList();
                    for (int i =0; i < lines.Count; i++)
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
                                try
                                {
                                    File.WriteAllLines(iniPath, lines);
                                }
                                catch (Exception ex)
                                {
                                    throw new LdapIniFileWriteException(ex.Message);
                                }
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
            catch (LdapSetupException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
                logger.Error(ex, $"RecordLdapServerDetailsSimple exception: {response.ErrorMessage}");
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}");
                return response;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = 4020;
                logger.Error(ex, $"RecordLdapServerDetailsSimple exception: {response.ErrorMessage}");
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
        }

        /// <summary>
        /// Saves (adds or updates) a user or group entry with the specified permission in the INI file.
        /// </summary>
        /// <param name="name">The user or group name.</param>
        /// <param name="type">The entry type: "U" for user, "G" for group.</param>
        /// <param name="permissionType">The permission type: "A" for Admin, "O" for Operator.</param>
        /// <returns>A LdapResponse indicating the result of the operation.</returns>
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
                    throw new LdapIniFileNotFoundException();
                }
                if (type != "U" && type != "G")
                {
                    throw new LdapInvalidEntryTypeException(type);
                }
                if (permissionType != "A" && permissionType != "O")
                {
                    throw new LdapInvalidPermissionTypeException(permissionType);
                }
                // Read all lines from the INI file
                var lines = File.ReadAllLines(iniPath).ToList();
                bool found = false;

                // Only skip adding if the exact entry already exists
                foreach (var line in lines)
                {
                    var parts = line.Split(',');
                    if (parts.Length >=3 && parts[0] == name && parts[1] == type && parts[2] == permissionType)
                    {
                        found = true;
                        logger.Info($"Entry for {name} ({type}) with permission {permissionType} already exists in INI file.");
                        break;
                    }
                }

                if (!found)
                {
                    // Append new entry for this permission
                    lines.Add($"{name},{type},{permissionType}");
                    logger.Info($"Added new permission entry for {name} ({type}) with permission {permissionType}.");
                }
                try
                {
                    // Write all lines back to the INI file
                    File.WriteAllLines(iniPath, lines);
                }
                catch (Exception ex)
                {
                    throw new LdapIniFileWriteException(ex.Message);
                }
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
            catch (LdapSetupException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
                logger.Error(ex, $"SaveLdapPermission exception: {response.ErrorMessage}");
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = 4020;
                logger.Error(ex, $"SaveLdapPermission exception: {response.ErrorMessage}");
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
        }

        /// <summary>
        /// Clears all user and group entries from the INI file, keeping only comments and the server details line.
        /// </summary>
        /// <returns>A LdapResponse indicating the result of the operation.</returns>
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
                    throw new LdapIniFileNotFoundException();
                }
                // Keep only comment lines, empty lines, and the server details line
                var lines = File.ReadAllLines(iniPath)
                    .Where(line => line.Trim().StartsWith("#") || string.IsNullOrWhiteSpace(line) || line.Trim().StartsWith("Server:"))
                    .ToList();
                try
                {
                    // Write the filtered lines back to the INI file
                    File.WriteAllLines(iniPath, lines);
                }
                catch (Exception ex)
                {
                    throw new LdapIniFileWriteException(ex.Message);
                }
                logger.Info("Cleared all user and group permissions from INI file.");
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
            catch (LdapSetupException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
                logger.Error(ex, $"ClearLdapPermissions exception: {response.ErrorMessage}");
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = 4020;
                logger.Error(ex, $"ClearLdapPermissions exception: {response.ErrorMessage}");
                logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
                return response;
            }
        }

        /// <summary>
        /// Gets user information from LDAP by user name.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="userName">The user name to search for.</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <returns>A LdapResponse containing the user information.</returns>
        // LDAP passthrough functions
        public static LdapResponse GetUser(string ldapPath, string userName, string username, string password)
        {
            var response = new LdapResponse();
            try
            {
                response.ResultArray = LDAP_Functions.GetUserByUserNameSimple(ldapPath, userName, username, password);
            }
            catch (LdapFunctionsException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Gets group information from LDAP by group name.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="groupName">The group name to search for.</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <returns>A LdapResponse containing the group information.</returns>
        public static LdapResponse GetGroup(string ldapPath, string groupName, string username, string password)
        {
            var response = new LdapResponse();
            try
            {
                response.ResultArray = LDAP_Functions.GetGroupByNameSimple(ldapPath, groupName, username, password);
            }
            catch (LdapFunctionsException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Gets all groups from LDAP.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <returns>A LdapResponse containing all group names.</returns>
        public static LdapResponse GetAllGroups(string ldapPath, string username, string password)
        {
            var response = new LdapResponse();
            try
            {
                response.ResultArray = LDAP_Functions.GetAllLdapGroupsArray(ldapPath, username, password);
            }
            catch (LdapFunctionsException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Gets all users in a specified group from LDAP.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="groupName">The group name to search for.</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <returns>A LdapResponse containing all users in the group.</returns>
        public static LdapResponse GetUsersInGroup(string ldapPath, string groupName, string username, string password)
        {
            var response = new LdapResponse();
            try
            {
                response.ResultArray = LDAP_Functions.GetUsersInGroupArray(ldapPath, groupName, username, password);
            }
            catch (LdapFunctionsException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Tests the connection to the LDAP server by pinging the host.
        /// </summary>
        /// <param name="host">The host name or IP address of the LDAP server.</param>
        /// <returns>A LdapResponse indicating if the connection was successful.</returns>
        public static LdapResponse TestConnection(string host)
        {
            var response = new LdapResponse();
            try
            {
                LDAP_Functions.PingServerSimple(host);
                response.Success = true;
            }
            catch (LdapPingFailedException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Tests the LDAP credentials by attempting to bind to the server.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <returns>A LdapResponse indicating if the credentials are valid.</returns>
        public static LdapResponse TestLdapCredentials(string ldapPath, string username, string password)
        {
            var response = new LdapResponse();
            try
            {
                LDAP_Functions.TestLdapConnection(ldapPath, username, password);
                response.Success = true;
            }
            catch (LdapDirectoryQueryException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Gets all members (users and groups) of a specified group from LDAP.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="groupName">The group name to search for.</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <returns>A LdapResponse containing all members of the group.</returns>
        public static LdapResponse GetAllGroupMembers(string ldapPath, string groupName, string username, string password)
        {
            var response = new LdapResponse();
            try
            {
                var members = LDAP_Functions.GetAllGroupMembers(ldapPath, groupName, username, password);
                if (members != null)
                {
                    // Convert to string array for ResultArray (format: "Name (Type)")
                    response.ResultArray = members.Select(m => $"{m.Name} ({m.Type})").ToArray();
                    response.Success = true;
                }
                else
                {
                    response.ResultArray = new string[0];
                    response.Success = true;
                }
            }
            catch (LdapFunctionsException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = 4020;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Gets all groups for a specified user from LDAP.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="userName">The user name to search for.</param>
        /// <param name="username">The LDAP username for authentication.</param>
        /// <param name="password">The LDAP password for authentication.</param>
        /// <returns>A LdapResponse containing all groups for the user.</returns>
        public static LdapResponse GetGroupsForUser(string ldapPath, string userName, string username, string password)
        {
            var response = new LdapResponse();
            try
            {
                response.ResultArray = LDAP_Functions.GetGroupsForUserArray(ldapPath, userName, username, password);
                response.Success = true;
            }
            catch (LdapFunctionsException ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = ex.ErrorNumber;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.ErrorMessage = ex.Message;
                response.ErrorNumber = 4020;
            }
            logger.Info($"LdapResponse: Success={response.Success}, ErrorNumber={response.ErrorNumber}, ErrorMessage={response.ErrorMessage}, ResultString={response.ResultString}, ResultArray=[{(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "")}]");
            return response;
        }

        /// <summary>
        /// Checks if a server is recorded in the LDAP.ini file.
        /// </summary>
        /// <returns>True if a server is recorded; otherwise, false.</returns>
        // Checks if a server is recorded in LDAP.ini
        public static bool IsServerRecorded()
        {
            string iniPath = GetIniPath();
            if (!File.Exists(iniPath)) return false;
            var lines = File.ReadAllLines(iniPath);
            return lines.Any(line => line.Trim().StartsWith("Server:"));
        }
    }
}
