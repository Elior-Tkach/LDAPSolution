using System;

namespace LDAPConsoleTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // LDAP settings (for testing, hardcoded)
            string ldapUrl = "192.168.20.228";
            var userGroups = new[] { "Engineering" };
            var adminGroups = new[] { "Admins", "IT_Support" };

            // Ask user for credentials
            Console.Write("Username: ");
            string username = Console.ReadLine();
            Console.Write("Password: ");
            string password = ReadPassword();
            using var ldap = new LdapService(ldapUrl, username, password, userGroups, adminGroups);

            // Test Init
            var (valid, error) = ldap.Init();
            if (!valid)
            {
                Console.WriteLine($"Init failed: {error}");
                return;
            }
            Console.WriteLine("Init successful.");



            var loginResult = ldap.Login(username, password);
            Console.WriteLine($"Authenticated: {loginResult.IsAuthenticated}");
            Console.WriteLine($"Is Admin: {loginResult.IsAdmin}");
            Console.WriteLine($"Is User: {loginResult.IsUser}");
            Console.WriteLine($"Error: {loginResult.ErrorMessage}");

            // Test Request
            Console.WriteLine($"Inactivity Timeout: {ldap.Request("InactivityTimeout")} minutes");
        }

        // Helper to read password without showing it
        private static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password.Substring(0, password.Length - 1);
                    Console.Write("\b \b");
                }
            } while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();
            return password;
        }
    }
}
  