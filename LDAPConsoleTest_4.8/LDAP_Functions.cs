using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net.NetworkInformation;
using System.IO;
using System.Reflection;

namespace LDAPConsoleTest_4._8
{
    public class LDAP_Functions
    {
        private static string GetIniPath()
        {
            var dllPath = Assembly.GetExecutingAssembly().Location;
            var dir = Path.GetDirectoryName(dllPath);
            return Path.Combine(dir, "LDAP.ini");
        }

        // Writes server data as the header if not present
        public static void RecordLdapServerDetails(string host, string username)
        {
            string iniPath = GetIniPath();
            if (!File.Exists(iniPath))
            {
                string header = $"# Server: Host={host}, Username={username}, Timestamp={DateTime.Now:yyyy-MM-dd HH:mm:ss}{Environment.NewLine}";
                header += "Name,Type,PermissionType,Timestamp" + Environment.NewLine;
                File.WriteAllText(iniPath, header);
            }
        }

        // Appends a user or group entry
        public static void RecordLdapEntry(string name, string type, string permissionType)
        {
            string iniPath = GetIniPath();
            string entry = $"{name},{type},{permissionType},{DateTime.Now:yyyy-MM-dd HH:mm:ss}{Environment.NewLine}";
            File.AppendAllText(iniPath, entry);
        }

        // Deprecated: keep for compatibility, but redirect to new method
        public static void RecordLdapUserDetails(string userName, string displayName = null, string email = null)
        {
            // For users, you can choose to use displayName/email in the name or ignore
            RecordLdapEntry(userName, "User", "A"); // Default permissionType 'A', adjust as needed
        }

        public static void RecordLdapGroupDetails(string groupName, string description = null)
        {
            RecordLdapEntry(groupName, "Group", "A"); // Default permissionType 'A', adjust as needed
        }

        /// <summary>
        /// Pings the specified server to check its availability.
        /// </summary>
        /// <param name="host">The hostname or IP address of the server.</param>
        /// <param name="errorMessage">The error message if the ping fails, otherwise null.</param>
        /// <returns>True if the server responds to the ping, otherwise false.</returns>
        public static bool PingServer(string host, out string errorMessage)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var reply = ping.Send(host);
                    if (reply.Status == IPStatus.Success)
                    {
                        errorMessage = null;
                        return true;
                    }
                    else
                    {
                        errorMessage = $"Ping failed: {reply.Status}";
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                errorMessage = $"Ping exception: {ex.Message}";
                return false;
            }
        }

        public static List<string> GetAllLdapGroups(string ldapPath, out string errorMessage, string username = null, string password = null)
        {
            var groups = new List<string>();
            errorMessage = null;
            try
            {
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = "(objectClass=group)";
                    searcher.PropertiesToLoad.Add("sAMAccountName");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        if (result.Properties.Contains("sAMAccountName"))
                        {
                            var groupName = result.Properties["sAMAccountName"][0]?.ToString();
                            if (!string.IsNullOrEmpty(groupName))
                            {
                                groups.Add(groupName);
                            }
                        }
                    }
                }
            }
            catch (System.Runtime.InteropServices.COMException comEx)
            {
                errorMessage = $"LDAP COM Exception: {comEx.Message}";
            }
            catch (UnauthorizedAccessException uaEx)
            {
                errorMessage = $"LDAP Unauthorized Access: {uaEx.Message}";
            }
            catch (Exception ex)
            {
                errorMessage = $"LDAP General Exception: {ex.Message}";
            }
            return groups;
        }

        public static List<string> GetUsersInGroup(string ldapPath, out string errorMessage, string groupName, string username = null, string password = null)
        {
            var users = new List<string>();
            errorMessage = null;
            try
            {
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("member");

                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        errorMessage = $"Group '{groupName}' not found.";
                        return users;
                    }

                    if (result.Properties.Contains("member"))
                    {
                        // Extract the base LDAP path server part (e.g., LDAP://192.168.20.228)
                        string serverPath = ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase)
                            ? ldapPath
                            : $"LDAP://{ldapPath}";

                        foreach (var memberDn in result.Properties["member"])
                        {
                            // Append the DN to the server path
                            using (var memberEntry = new DirectoryEntry($"{serverPath}/{memberDn}", username, password))
                            {
                                var userAccount = memberEntry.Properties["sAMAccountName"].Value as string;
                                if (!string.IsNullOrEmpty(userAccount))
                                {
                                    users.Add(userAccount);
                                }
                            }
                        }
                    }
                }
            }
            catch (System.Runtime.InteropServices.COMException comEx)
            {
                errorMessage = $"LDAP COM Exception: {comEx.Message}";
            }
            catch (UnauthorizedAccessException uaEx)
            {
                errorMessage = $"LDAP Unauthorized Access: {uaEx.Message}";
            }
            catch (Exception ex)
            {
                errorMessage = $"LDAP General Exception: {ex.Message}";
            }
            return users;
        }


        public static DirectoryEntry GetUserByUserName(string ldapPath, out string errorMessage, string userName, string username = null, string password = null)
        {
            errorMessage = null;
            try
            {
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    // Search by sAMAccountName, givenName (first name), or sn (last name)
                    searcher.Filter = $"(&(objectClass=user)(|(sAMAccountName=*{userName}*)(givenName=*{userName}*)(sn=*{userName}*)(cn=*{userName}*)(displayName=*{userName}*)))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("displayName");
                    searcher.PropertiesToLoad.Add("mail");
                    searcher.PropertiesToLoad.Add("givenName");
                    searcher.PropertiesToLoad.Add("sn");

                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        errorMessage = $"User '{userName}' not found.";
                        return null;
                    }

                    // Return a new DirectoryEntry for the found user
                    return result.GetDirectoryEntry();
                }
            }
            catch (System.Runtime.InteropServices.COMException comEx)
            {
                errorMessage = $"LDAP COM Exception: {comEx.Message}";
            }
            catch (UnauthorizedAccessException uaEx)
            {
                errorMessage = $"LDAP Unauthorized Access: {uaEx.Message}";
            }
            catch (Exception ex)
            {
                errorMessage = $"LDAP General Exception: {ex.Message}";
            }
            return null;
        }

        public static DirectoryEntry GetGroupByName(string ldapPath, out string errorMessage, string groupName, string username = null, string password = null)
        {
            errorMessage = null;
            try
            {
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");

                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        errorMessage = $"Group '{groupName}' not found.";
                        return null;
                    }

                    // Return a new DirectoryEntry for the found group
                    return result.GetDirectoryEntry();
                }
            }
            catch (System.Runtime.InteropServices.COMException comEx)
            {
                errorMessage = $"LDAP COM Exception: {comEx.Message}";
            }
            catch (UnauthorizedAccessException uaEx)
            {
                errorMessage = $"LDAP Unauthorized Access: {uaEx.Message}";
            }
            catch (Exception ex)
            {
                errorMessage = $"LDAP General Exception: {ex.Message}";
            }
            return null;
        }

        public static List<string> GetGroupsForUser(string ldapPath, out string errorMessage, string userName, string username = null, string password = null)
        {
            var groups = new List<string>();
            errorMessage = null;
            try
            {
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=user)(sAMAccountName={userName}))";
                    searcher.PropertiesToLoad.Add("memberOf");

                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        errorMessage = $"User '{userName}' not found.";
                        return groups;
                    }

                    if (result.Properties.Contains("memberOf"))
                    {
                        foreach (var groupDn in result.Properties["memberOf"])
                        {
                            // Extract the CN (common name) of the group from the distinguished name
                            var dn = groupDn.ToString();
                            var cnPrefix = "CN=";
                            var cnStart = dn.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
                            if (cnStart >= 0)
                            {
                                var cnEnd = dn.IndexOf(',', cnStart);
                                if (cnEnd > cnStart)
                                {
                                    var groupName = dn.Substring(cnStart + cnPrefix.Length, cnEnd - (cnStart + cnPrefix.Length));
                                    groups.Add(groupName);
                                }
                                else
                                {
                                    groups.Add(dn.Substring(cnStart + cnPrefix.Length));
                                }
                            }
                        }
                    }
                }
            }
            catch (System.Runtime.InteropServices.COMException comEx)
            {
                errorMessage = $"LDAP COM Exception: {comEx.Message}";
            }
            catch (UnauthorizedAccessException uaEx)
            {
                errorMessage = $"LDAP Unauthorized Access: {uaEx.Message}";
            }
            catch (Exception ex)
            {
                errorMessage = $"LDAP General Exception: {ex.Message}";
            }
            return groups;
        }
    }
}
