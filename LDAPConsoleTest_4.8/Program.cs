using System;
using System.Collections.Generic;

namespace LDAPConsoleTest_4._8
{
    class Program
    {
        static void Main()
        {
            // Step 1: Ask for server details
            Console.Write("Enter LDAP server host (e.g., ldap://yourserver): ");
            string host = Console.ReadLine();
            Console.Write("Enter LDAP username: ");
            string username = Console.ReadLine();
            Console.Write("Enter LDAP password: ");
            string password = ReadPassword();

            // After reading host from user:
            string ldapPath = host.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase) ? host : "LDAP://" + host;

            // Step 2: Test connection
            string errorMessage;
            bool pingResult = LDAP_Functions.PingServer(host, out errorMessage);
            if (pingResult)
            {
                Console.WriteLine("Connection successful.");
                LDAP_Functions.RecordLdapServerDetails(host, username);
            }
            else
            {
                Console.WriteLine("Connection failed: " + errorMessage);
                return;
            }

            // Step 3: Action menu
            Console.WriteLine("Choose an action:");
            Console.WriteLine("1) Find user by name");
            Console.WriteLine("2) Find group by name");
            Console.WriteLine("3) Select user from specific group");
            Console.WriteLine("4) Select group from list of all groups");
            Console.Write("Enter your choice (1-4): ");
            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    Console.Write("Enter user name: ");
                    string userName = Console.ReadLine();
                    var user = LDAP_Functions.GetUserByUserName(ldapPath, out errorMessage, userName, username, password);
                    if (user != null)
                    {
                        Console.WriteLine("User found: " + user.Properties["sAMAccountName"].Value);
                        string displayName = user.Properties["displayName"].Value as string;
                        string email = user.Properties["mail"].Value as string;
                        AskAndRecordUser(userName, displayName, email);
                    }
                    else
                    {
                        Console.WriteLine("User not found: " + errorMessage);
                    }
                    break;
                case "2":
                    Console.Write("Enter group name: ");
                    string groupName = Console.ReadLine();
                    var group = LDAP_Functions.GetGroupByName(ldapPath, out errorMessage, groupName, username, password);
                    if (group != null)
                    {
                        Console.WriteLine("Group found: " + group.Properties["sAMAccountName"].Value);
                        string description = group.Properties["description"].Value as string;
                        AskAndRecordGroup(groupName, description);
                    }
                    else
                    {
                        Console.WriteLine("Group not found: " + errorMessage);
                    }
                    break;
                case "3":
                    Console.Write("Enter group name: ");
                    string groupNameForUser = Console.ReadLine();
                    var users = LDAP_Functions.GetUsersInGroup(ldapPath, out errorMessage, groupNameForUser, username, password);
                    if (users.Count > 0)
                    {
                        Console.WriteLine("Users in group:");
                        for (int i = 0; i < users.Count; i++)
                        {
                            Console.WriteLine($"{i + 1}: {users[i]}");
                        }
                        Console.Write("Select user number: ");
                        if (int.TryParse(Console.ReadLine(), out int userIndex) && userIndex > 0 && userIndex <= users.Count)
                        {
                            string selectedUser = users[userIndex - 1];
                            var selectedUserEntry = LDAP_Functions.GetUserByUserName(ldapPath, out errorMessage, selectedUser, username, password);
                            string displayName = selectedUserEntry?.Properties["displayName"].Value as string;
                            string email = selectedUserEntry?.Properties["mail"].Value as string;
                            AskAndRecordUser(selectedUser, displayName, email);
                        }
                    }
                    else
                    {
                        Console.WriteLine("No users found or error: " + errorMessage);
                    }
                    break;
                case "4":
                    var allGroups = LDAP_Functions.GetAllLdapGroups(ldapPath, out errorMessage, username, password);
                    if (allGroups.Count > 0)
                    {
                        Console.WriteLine("All groups:");
                        for (int i = 0; i < allGroups.Count; i++)
                        {
                            Console.WriteLine($"{i + 1}: {allGroups[i]}");
                        }
                        Console.Write("Select group number: ");
                        if (int.TryParse(Console.ReadLine(), out int groupIndex) && groupIndex > 0 && groupIndex <= allGroups.Count)
                        {
                            string selectedGroup = allGroups[groupIndex - 1];
                            var selectedGroupEntry = LDAP_Functions.GetGroupByName(ldapPath, out errorMessage, selectedGroup, username, password);
                            string description = selectedGroupEntry?.Properties["description"].Value as string;
                            AskAndRecordGroup(selectedGroup, description);
                        }
                    }
                    else
                    {
                        Console.WriteLine("No groups found or error: " + errorMessage);
                    }
                    break;
                default:
                    Console.WriteLine("Invalid choice.");
                    break;
            }
          }

        static void AskAndRecordUser(string userName, string displayName, string email)
        {
            Console.Write("Record this user in LDAP_users.ini? (y/n): ");
            if (Console.ReadLine().Trim().ToLower() == "y")
            {
                LDAP_Functions.RecordLdapUserDetails(userName, displayName, email);
                Console.WriteLine("User recorded.");
            }
        }

        static void AskAndRecordGroup(string groupName, string description)
        {
            Console.Write("Record this group in LDAP_groups.ini? (y/n): ");
            if (Console.ReadLine().Trim().ToLower() == "y")
            {
                LDAP_Functions.RecordLdapGroupDetails(groupName, description);
                Console.WriteLine("Group recorded.");
            }
        }

        static string ReadPassword()
        {
            var pwd = string.Empty;
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pwd.Length > 0)
                {
                    pwd = pwd.Substring(0, pwd.Length - 1);
                    Console.Write("\b \b");
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    pwd += keyInfo.KeyChar;
                    Console.Write("*");
                }
            } while (key != ConsoleKey.Enter);
            Console.WriteLine();
            return pwd;
        }
    }
}
