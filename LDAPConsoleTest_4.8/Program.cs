using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LDAPConsoleTest_4._8
{

    class Program
    {
        static void Main()
        {
            List<string> groups = new List<string>();
            int result = Authenticator.AuthenticateUser("john.doe", "P@ssw0rd", ref groups);

            Console.WriteLine("Result Code: " + result);
            if (result == 0)
            {
                Console.WriteLine("Authentication successful. User groups:");
                foreach (var g in groups)
                {
                    Console.WriteLine(g);
                }
            }
        }
    }
}
