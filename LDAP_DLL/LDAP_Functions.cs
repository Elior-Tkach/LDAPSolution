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
        public static string[] GetAllLdapGroupsArray(string ldapPath, string username, string password)
        {
            logger.Info($"GetAllLdapGroupsArray called with ldapPath: {ldapPath}, username: {username}");
            try
            {
                var groups = new List<string>();
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
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

        public static string[] GetUsersInGroupArray(string ldapPath, string groupName, string username, string password)
        {
            logger.Info($"GetUsersInGroupArray called with ldapPath: {ldapPath}, groupName: {groupName}, username: {username}");
            try
            {
                var users = new List<string>();
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("member");
                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        throw new LdapDirectoryGroupNotFoundException(groupName);
                    }
                    if (result.Properties.Contains("member"))
                    {
                        string serverPath = ldapPath;
                        foreach (var memberDn in result.Properties["member"])
                        {
                            using (var memberEntry = new DirectoryEntry($"{serverPath}/{memberDn}", username, password))
                            {
                                var userAccount = memberEntry.Properties["sAMAccountName"].Value as string;
                                if (!string.IsNullOrEmpty(userAccount))
                                    users.Add(userAccount);
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
                    searcher.Filter = $"(&(objectClass=user)(|(sAMAccountName=*{userName}*)(displayName=*{userName}*)))";
                    searcher.PropertiesToLoad.Add("memberOf");
                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        throw new LdapDirectoryUserNotFoundException(userName);
                    }
                    if (result.Properties.Contains("memberOf"))
                    {
                        foreach (var groupDn in result.Properties["memberOf"])
                        {
                            var dn = groupDn.ToString();
                            var cnPrefix = "CN=";
                            var cnStart = dn.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
                            if (cnStart >= 0)
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
        public static string[] GetUserByUserNameSimple(string ldapPath, string userName, string username, string password)
        {
            logger.Info($"GetUserByUserNameSimple called with ldapPath: {ldapPath}, userName: {userName}, username: {username}");
            var userNames = new List<string>();
            try
            {
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=user)(|(sAMAccountName=*{userName}*)(givenName=*{userName}*)(sn=*{userName}*)(cn=*{userName}*)(displayName=*{userName}*)))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    var results = searcher.FindAll();
                    if (results == null || results.Count == 0)
                    {
                        throw new LdapDirectoryUserNotFoundException(userName);
                    }
                    foreach (SearchResult result in results)
                    {
                        var userEntry = result.GetDirectoryEntry();
                        var sAMAccountName = GetProperty(userEntry, "sAMAccountName");
                        if (!string.IsNullOrEmpty(sAMAccountName))
                        {
                            userNames.Add(sAMAccountName);
                        }
                    }
                    logger.Info($"Users found: {string.Join(", ", userNames)}");
                    return userNames.ToArray();
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

        public static string GetGroupByNameSimple(string ldapPath, string groupName, string username, string password)
        {
            logger.Info($"GetGroupByNameSimple called with ldapPath: {ldapPath}, groupName: {groupName}, username: {username}");
            try
            {
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        throw new LdapDirectoryGroupNotFoundException(groupName);
                    }
                    var groupEntry = result.GetDirectoryEntry();
                    var sb = new StringBuilder();
                    sb.Append(GetProperty(groupEntry, "sAMAccountName"));
                    logger.Info($"Group found: {sb.ToString()}");
                    return sb.ToString();
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

        // -------------------------
        // Helpers
        // -------------------------
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

        public static List<LdapGroupMember> GetAllGroupMembers(string ldapPath, string groupName, string username, string password)
        {
            var members = new List<LdapGroupMember>();
            try
            {
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                    searcher.PropertiesToLoad.Add("member");
                    var result = searcher.FindOne();
                    if (result == null)
                        throw new LdapDirectoryGroupNotFoundException(groupName);

                    if (result.Properties.Contains("member"))
                    {
                        foreach (var memberDn in result.Properties["member"])
                        {
                            using (var memberEntry = new DirectoryEntry($"{ldapPath}/{memberDn}", username, password))
                            {
                                var objectClass = memberEntry.Properties["objectClass"];
                                var name = memberEntry.Properties["sAMAccountName"].Value as string;
                                if (string.IsNullOrEmpty(name))
                                    name = memberEntry.Properties["cn"].Value as string;

                                string type = "Unknown";
                                if (objectClass != null)
                                {
                                    var classes = objectClass.Cast<object>().Select(c => c.ToString()).ToList();
                                    if (classes.Contains("user"))
                                        type = "User";
                                    else if (classes.Contains("group"))
                                        type = "Group";
                                }

                                if (!string.IsNullOrEmpty(name))
                                {
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
    }
}
