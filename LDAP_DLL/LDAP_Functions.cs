using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.Net.NetworkInformation;


namespace LDAP_DLL
{
    public class LDAP_Functions
    {
        // -------------------------
        // Basic Ping method
        // -------------------------
        public static bool PingServerSimple(string host, out string errorMessage)
        {
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
                        catch
                        {
                            resolvedHostName = "N/A";
                            resolvedIps = "N/A";
                        }

                        errorMessage = $"Ping succeeded. IPs: {resolvedIps}, HostName: {resolvedHostName}";
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

        // -------------------------
        // Group & User Queries
        // -------------------------
        public static string[] GetAllLdapGroupsArray(string ldapPath, out string errorMessage, string username, string password)
        {
            try
            {
                var groups = new List<string>();
                errorMessage = null;
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
                return groups.ToArray();
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return new string[0];
            }
        }

        public static string[] GetUsersInGroupArray(string ldapPath, out string errorMessage, string groupName, string username, string password)
        {
            try
            {
                var users = new List<string>();
                errorMessage = null;
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
                        errorMessage = $"Group '{groupName}' not found.";
                        return users.ToArray();
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
                return users.ToArray();
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return new string[0];
            }
        }

        public static string[] GetGroupsForUserArray(string ldapPath, out string errorMessage, string userName, string username, string password)
        {
            try
            {
                var groups = new List<string>();
                errorMessage = null;
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass=user)(sAMAccountName={userName}))";
                    searcher.PropertiesToLoad.Add("memberOf");
                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        errorMessage = $"User '{userName}' not found.";
                        return groups.ToArray();
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
                return groups.ToArray();
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return new string[0];
            }
        }

        // -------------------------
        // Lookup by Username/Group
        // -------------------------
        public static string GetUserByUserNameSimple(string ldapPath, out string errorMessage, string userName, string username, string password)
        {
            try
            {
                errorMessage = null;
                if (!ldapPath.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                    ldapPath = "LDAP://" + ldapPath;
                using (var entry = new DirectoryEntry(ldapPath, username, password))
                using (var searcher = new DirectorySearcher(entry))
                {
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
                        return string.Empty;
                    }
                    var userEntry = result.GetDirectoryEntry();
                    var sb = new StringBuilder();
                    sb.Append("sAMAccountName=").Append(GetProperty(userEntry, "sAMAccountName")).Append(";");
                    sb.Append("displayName=").Append(GetProperty(userEntry, "displayName")).Append(";");
                    sb.Append("mail=").Append(GetProperty(userEntry, "mail")).Append(";");
                    sb.Append("givenName=").Append(GetProperty(userEntry, "givenName")).Append(";");
                    sb.Append("sn=").Append(GetProperty(userEntry, "sn"));
                    return sb.ToString();
                }
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return string.Empty;
            }
        }

        public static string GetGroupByNameSimple(string ldapPath, out string errorMessage, string groupName, string username, string password)
        {
            try
            {
                errorMessage = null;
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
                        errorMessage = $"Group '{groupName}' not found.";
                        return string.Empty;
                    }
                    var groupEntry = result.GetDirectoryEntry();
                    var sb = new StringBuilder();
                    sb.Append("sAMAccountName=").Append(GetProperty(groupEntry, "sAMAccountName"));
                    return sb.ToString();
                }
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return string.Empty;
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
    }
}
