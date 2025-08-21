using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LDAPConsoleTest
{
    public class AuthResult
    {
        public bool IsAuthenticated { get; set; }
        public bool IsUser { get; set; }
        public bool IsAdmin { get; set; }
        public string ErrorMessage { get; set; }
    }
}
