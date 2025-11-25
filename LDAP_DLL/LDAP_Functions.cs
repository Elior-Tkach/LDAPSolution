using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.Net.NetworkInformation;
using NLog;

namespace LDAP_DLL
{
    internal class LDAP_Functions
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        // -------------------------
        // Basic Ping method
        // -------------------------
        /// <summary>
        /// Pings the specified host to check if it is reachable and logs the result.
        /// </summary>
        /// <param name="host">The host name or IP address to ping.</param>
        /// <returns>True if the ping is successful; otherwise, throws an exception.</returns>
        public static bool PingServerSimple(string host)
        {
            logger.Info($"PingServerSimple called with host: {host}");
            try
            {
                using (var ping = new Ping())
                {
                    var reply = ping.Send(host);
                    if (reply.Status == IPStatus.Success)
                    {
                        string resolvedHostName = null;
                        string resolvedIps = null;
                        try
                        {
                            // Try to resolve host name and ALL IPs
                            var hostEntry = System.Net.Dns.GetHostEntry(host);
                            resolvedHostName = hostEntry.HostName;
                            resolvedIps = hostEntry.AddressList.Length > 0
                                ? string.Join(", ", hostEntry.AddressList.Select(a => a.ToString()))
                                : "N/A";
                        }
                        catch (Exception ex)
                        {
                            logger.Warn(ex, $"Failed to resolve host name or IPs for host: {host}");
                            resolvedHostName = "N/A";
                            resolvedIps = "N/A";
                        }
                        string pingInfo = $"Ping succeeded. IPs: {resolvedIps}, HostName: {resolvedHostName}";
                        logger.Info(pingInfo);
                        return true;
                    }
                    else
                    {
                        string errorMessage = $"Ping failed: {reply.Status}";
                        logger.Warn(errorMessage);
                        throw new LdapPingFailedException(errorMessage);
                    }
                }
            }
            catch (LdapPingFailedException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string errorMessage = $"Ping exception: {ex.Message}";
                logger.Error(ex, errorMessage);
                throw new LdapPingFailedException(errorMessage);
            }
        }

        /// <summary>
        /// Tests the LDAP connection by attempting to bind with the provided credentials.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        public static void TestLdapConnection(string ldapPath, string username, string password)
        {
            try
            {
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                {
                    // Force authentication by accessing a property
                    var nativeObj = entry.NativeObject;
                }
            }
            catch (Exception ex)
            {
                throw new LdapDirectoryQueryException(ex.Message);
            }
        } 
        // -------------------------
        // Group & User Queries
        // -------------------------
        /// <summary>
        /// Gets all LDAP groups from the directory for the specified credentials.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <returns>An array of group names.</returns>
        public static string[] GetAllLdapGroupsArray(string ldapPath, string username, string password)
        {
            logger.Info($"GetAllLdapGroupsArray called with ldapPath: {ldapPath}, username: {username}");
            try
            {
                var groups = new List<string>();
                // Ensure LDAP path is in correct format
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                // Connect to LDAP directory with provided credentials
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    // Search for all group objects in LDAP
                    searcher.Filter = "(objectClass=group)";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    // Find all group entries in LDAP
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        if (result.Properties.Contains("sAMAccountName"))
                        {
                            var groupName = result.Properties["sAMAccountName"][0]?.ToString();
                            if (!string.IsNullOrEmpty(groupName))
                                groups.Add(groupName);
                        }
                    }
                }
                logger.Info($"Found {groups.Count} groups.");
                return groups.ToArray();
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"GetAllLdapGroupsArray failed: {ex.Message}");
                throw new LdapDirectoryQueryException(ex.Message);
            }
        }

        /// <summary>
        /// Gets all users in a specified group, including their username, first name, and last name.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="groupName">The group name to search for.</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <returns>An array of strings in the format "username,FirstName,LastName" for each user in the group.</returns>
        public static string[] GetUsersInGroupArray(string ldapPath, string groupName, string username, string password)
        {
            logger.Info($"GetUsersInGroupArray called with ldapPath: {ldapPath}, groupName: {groupName}, username: {username}");
            try
            {
                var users = new List<string>();
                // Ensure LDAP path is in correct format
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                // Connect to LDAP directory with provided credentials
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    // Search for the group by sAMAccountName
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("member");
                    // Find the group entry in LDAP
                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        // Group not found in directory
                        throw new LdapDirectoryGroupNotFoundException(groupName);
                    }
                    if (result.Properties.Contains("member"))
                    {
                        string serverPath = ldapPath;
                        // Iterate over each member DN in the group
                        foreach (var memberDn in result.Properties["member"])
                        {
                            // Open DirectoryEntry for each member (user or group)
                            using (var memberEntry = new DirectoryEntry($"{serverPath}/{memberDn}", username, password))
                            {
                                // Get user properties from LDAP
                                var userAccount = memberEntry.Properties["sAMAccountName"].Value as string; // LDAP username
                                var givenName = memberEntry.Properties["givenName"].Value as string; // LDAP first name
                                var sn = memberEntry.Properties["sn"].Value as string; // LDAP last name
                                // Only add if userAccount is not null or empty
                                if (!string.IsNullOrEmpty(userAccount))
                                    users.Add($"{userAccount},{givenName},{sn}");
                            }
                        }
                    }
                }
                logger.Info($"Found {users.Count} users in group {groupName}.");
                return users.ToArray();
            }
            catch (LdapDirectoryGroupNotFoundException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"GetUsersInGroupArray failed: {ex.Message}");
                throw new LdapDirectoryQueryException(ex.Message);
            }
        }

        /// <summary>
        /// Gets all groups for a specified user.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="userName">The user name to search for.</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <returns>An array of group names the user belongs to.</returns>
        public static string[] GetGroupsForUserArray(string ldapPath, string userName, string username, string password)
        {
            logger.Info($"GetGroupsForUserArray called with ldapPath: {ldapPath}, userName: {userName}, username: {username}");
            try
            {
                var groups = new List<string>();
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    // Search for user by sAMAccountName or displayName
                    searcher.Filter = $"(&(objectClass=user)(|(sAMAccountName=*{userName}*)(displayName=*{userName}*)))";
                    searcher.PropertiesToLoad.Add("memberOf");
                    // Find the user entry in LDAP
                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        throw new LdapDirectoryUserNotFoundException(userName);
                    }
                    if (result.Properties.Contains("memberOf"))
                    {
                        // Iterate over all group DNs the user is a member of
                        foreach (var groupDn in result.Properties["memberOf"])
                        {
                            var dn = groupDn.ToString();
                            var cnPrefix = "CN=";
                            var cnStart = dn.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
                            if (cnStart >=0)
                            {
                                var cnEnd = dn.IndexOf(',', cnStart);
                                if (cnEnd > cnStart)
                                {
                                    var group = dn.Substring(cnStart + cnPrefix.Length, cnEnd - (cnStart + cnPrefix.Length));
                                    groups.Add(group);
                                }
                                else
                                {
                                    groups.Add(dn.Substring(cnStart + cnPrefix.Length));
                                }
                            }
                        }
                    }
                }
                logger.Info($"Found {groups.Count} groups for user {userName}.");
                return groups.ToArray();
            }
            catch (LdapDirectoryUserNotFoundException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"GetGroupsForUserArray failed: {ex.Message}");
                throw new LdapDirectoryQueryException(ex.Message);
            }
        }

        // -------------------------
        // Lookup by Username/Group
        // -------------------------
        /// <summary>
        /// Gets all users matching the specified user name, including their username, first name, and last name.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="userName">The user name to search for.</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <returns>An array of strings in the format "username,FirstName,LastName" for each user found.</returns>
        public static string[] GetUserByUserNameSimple(string ldapPath, string userName, string username, string password)
        {
            logger.Info($"GetUserByUserNameSimple called with ldapPath: {ldapPath}, userName: {userName}, username: {username}");
            var userInfos = new List<string>();
            try
            {
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                // Connect to LDAP directory with provided credentials
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    // Search for users matching the userName in various LDAP fields
                    searcher.Filter = $"(&(objectClass=user)(|(sAMAccountName=*{userName}*)(givenName=*{userName}*)(sn=*{userName}*)(cn=*{userName}*)(displayName=*{userName}*)))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("givenName");
                    searcher.PropertiesToLoad.Add("sn");
                    // Find all matching user entries in LDAP
                    var results = searcher.FindAll();
                    if (results == null || results.Count ==0)
                    {
                        throw new LdapDirectoryUserNotFoundException(userName);
                    }
                    foreach (SearchResult result in results)
                    {
                        var userEntry = result.GetDirectoryEntry();
                        // Get user properties from LDAP
                        var sAMAccountName = GetProperty(userEntry, "sAMAccountName"); // LDAP username
                        var givenName = GetProperty(userEntry, "givenName"); // LDAP first name
                        var sn = GetProperty(userEntry, "sn"); // LDAP last name
                        if (!string.IsNullOrEmpty(sAMAccountName))
                        {
                            userInfos.Add($"{sAMAccountName},{givenName},{sn}");
                        }
                    }
                    logger.Info($"Users found: {string.Join(", ", userInfos)}");
                    return userInfos.ToArray();
                }
            }
            catch (LdapDirectoryUserNotFoundException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"GetUserByUserNameSimple failed: {ex.Message}");
                throw new LdapDirectoryQueryException(ex.Message);
            }
        }

        /// <summary>
        /// Gets all groups matching the specified group name.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="groupName">The group name to search for.</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <returns>An array of group names found.</returns>
        public static string[] GetGroupByNameSimple(string ldapPath, string groupName, string username, string password)
        {
            logger.Info($"GetGroupByNameSimple called with ldapPath: {ldapPath}, groupName: {groupName}, username: {username}");
            var groupNames = new List<string>();
            try
            {
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    // Search for groups matching sAMAccountName, cn, or name
                    searcher.Filter = $"(&(objectClass=group)(|(sAMAccountName=*{groupName}*)(cn=*{groupName}*)(name=*{groupName}*)))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("cn");
                    searcher.PropertiesToLoad.Add("name");
                    // Find all matching group entries in LDAP
                    var results = searcher.FindAll();
                    if (results == null || results.Count ==0)
                    {
                        throw new LdapDirectoryGroupNotFoundException(groupName);
                    }
                    foreach (SearchResult result in results)
                    {
                        var groupEntry = result.GetDirectoryEntry();
                        // Get group properties from LDAP
                        var sAMAccountName = GetProperty(groupEntry, "sAMAccountName");
                        var cn = GetProperty(groupEntry, "cn");
                        var nameProp = GetProperty(groupEntry, "name");
                        if (!string.IsNullOrEmpty(sAMAccountName))
                        {
                            groupNames.Add(sAMAccountName);
                        }
                        else if (!string.IsNullOrEmpty(cn))
                        {
                            groupNames.Add(cn);
                        }
                        else if (!string.IsNullOrEmpty(nameProp))
                        {
                            groupNames.Add(nameProp);
                        }
                    }
                    logger.Info($"Groups found: {string.Join(", ", groupNames)}");
                    return groupNames.ToArray();
                }
            }
            catch (LdapDirectoryGroupNotFoundException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"GetGroupByNameSimple failed: {ex.Message}");
                throw new LdapDirectoryQueryException(ex.Message);
            }
        }

        /// <summary>
        /// Gets all members (users and groups) of a specified group.
        /// </summary>
        /// <param name="ldapPath">The LDAP path (server address).</param>
        /// <param name="groupName">The group name to search for.</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <returns>A list of LdapGroupMember objects representing the group's members.</returns>
        public static List<LdapGroupMember> GetAllGroupMembers(string ldapPath, string groupName, string username, string password)
        {
            var members = new List<LdapGroupMember>();
            try
            {
                // Ensure LDAP path is in correct format
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                // Connect to LDAP directory with provided credentials
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    // Search for the group by sAMAccountName
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("member");
                    // Find the group entry in LDAP
                    var result = searcher.FindOne();
                    if (result == null)
                        throw new LdapDirectoryGroupNotFoundException(groupName);

                    if (result.Properties.Contains("member"))
                    {
                        // Iterate over each member DN in the group
                        foreach (var memberDn in result.Properties["member"])
                        {
                            // Open DirectoryEntry for each member (user or group)
                            using (var memberEntry = new DirectoryEntry($"{ldapPath}/{memberDn}", username, password))
                            {
                                // Get objectClass property to determine if user or group
                                var objectClass = memberEntry.Properties["objectClass"];
                                // Get sAMAccountName (username) or cn (group name)
                                var name = memberEntry.Properties["sAMAccountName"].Value as string;
                                if (string.IsNullOrEmpty(name))
                                    name = memberEntry.Properties["cn"].Value as string;

                                string type = "Unknown";
                                if (objectClass != null)
                                {
                                    // Check if member is a user or group
                                    var classes = objectClass.Cast<object>().Select(c => c.ToString()).ToList();
                                    if (classes.Contains("user"))
                                        type = "User";
                                    else if (classes.Contains("group"))
                                        type = "Group";
                                }

                                if (!string.IsNullOrEmpty(name))
                                {
                                    // Add member info to the result list
                                    members.Add(new LdapGroupMember { Name = name, Type = type });
                                }
                            }
                        }
                    }
                }
                return members;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"GetAllGroupMembers failed: {ex.Message}");
                throw new LdapDirectoryQueryException(ex.Message);
            }
        }

        // -------------------------
        // Helpers
        // -------------------------
        /// <summary>
        /// Helper to get a property value from a DirectoryEntry, or empty string if not present.
        /// </summary>
        /// <param name="entry">The DirectoryEntry object.</param>
        /// <param name="propertyName">The property name to retrieve.</param>
        /// <returns>The property value as a string, or empty string if not found.</returns>
        private static string GetProperty(System.DirectoryServices.DirectoryEntry entry, string propertyName)
        {
            if (entry.Properties.Contains(propertyName) && entry.Properties[propertyName].Count > 0)
                return entry.Properties[propertyName][0]?.ToString() ?? string.Empty;
            return string.Empty;
        }

        public class LdapGroupMember
        {
            public string Name { get; set; }
            public string Type { get; set; } // "User" or "Group"
        }


    }
}
