using System;

namespace LDAP_DLL
{
    public class LdapResponse
    {
        /// <summary>
        /// True if the operation was successful
        /// </summary>
        public bool Success { get; set; } = true;

        /// <summary>
        /// Error number for custom exceptions (0 = no error)
        /// </summary>
        public int ErrorNumber { get; set; } = 0;

        /// <summary>
        /// Error message if the operation failed
        /// </summary>
        public string ErrorMessage { get; set; } = "";

        /// <summary>
        /// Optional string result (for functions returning single string, e.g., GetUser, GetGroup)
        /// </summary>
        public string ResultString { get; set; } = "";

        /// <summary>
        /// Optional array result (for functions returning multiple strings, e.g., GetAllGroups, GetUsersInGroup)
        /// </summary>
        public string[] ResultArray { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Optional boolean result (for functions returning true/false)
        /// </summary>
        public bool ResultBool { get; set; } = false;


    }
}
