using System;

namespace LDAP_DLL
{
    public class LdapSetupException : Exception
    {
        public int ErrorNumber { get; }
        public LdapSetupException(string message, int errorNumber) : base(message)
        {
            ErrorNumber = errorNumber;
        }
        public LdapSetupException(string message, int errorNumber, Exception inner) : base(message, inner)
        {
            ErrorNumber = errorNumber;
        }
    }

    public class LdapAuthenticationException : Exception
    {
        public int ErrorNumber { get; }
        public LdapAuthenticationException(string message, int errorNumber) : base(message)
        {
            ErrorNumber = errorNumber;
        }
        public LdapAuthenticationException(string message, int errorNumber, Exception inner) : base(message, inner)
        {
            ErrorNumber = errorNumber;
        }
    }

    // 4000: User not found
    public class LdapUserNotFoundException : LdapAuthenticationException
    {
        public LdapUserNotFoundException(string userName)
            : base($"User '{userName}' not found in INI file.", 4000) { }
    }

    // 4001: Permission mismatch
    public class LdapPermissionMismatchException : LdapAuthenticationException
    {
        public LdapPermissionMismatchException(string expected, string found)
            : base($"User found, but permission type does not match. Expected: {expected}, Found: {found}", 4001) { }
    }

    // 4002: INI file missing
    public class LdapIniFileNotFoundException : LdapSetupException
    {
        public LdapIniFileNotFoundException()
            : base("INI file does not exist.", 4002) { }
    }

    // 4003: LDAP IP not found in INI
    public class LdapIpNotFoundException : LdapSetupException
    {
        public LdapIpNotFoundException()
            : base("LDAP IP not found in INI file header.", 4003) { }
    }

    // 4004: User not in any group
    public class LdapUserNotInGroupException : LdapAuthenticationException
    {
        public LdapUserNotInGroupException(string userName)
            : base($"User '{userName}' does not belong to any groups or failed to retrieve groups.", 4004) { }
    }

    // 4005: No registered group with permission
    public class LdapNoRegisteredGroupException : LdapAuthenticationException
    {
        public LdapNoRegisteredGroupException(string permissionType)
            : base($"No registered group found for user in INI file with permission type '{permissionType}'.", 4005) { }
    }

    // 4006: Invalid permission type
    public class LdapInvalidPermissionTypeException : LdapSetupException
    {
        public LdapInvalidPermissionTypeException(string permissionType)
            : base($"Invalid permission type: '{permissionType}'. Allowed: A (Admin), O (Operator).", 4006) { }
    }

    // 4007: Invalid entry type
    public class LdapInvalidEntryTypeException : LdapSetupException
    {
        public LdapInvalidEntryTypeException(string entryType)
            : base($"Invalid entry type: '{entryType}'. Allowed: U (User), G (Group).", 4007) { }
    }

    // 4008: INI file write error
    public class LdapIniFileWriteException : LdapSetupException
    {
        public LdapIniFileWriteException(string message)
            : base($"Failed to write to INI file: {message}", 4008) { }
    }

    // 4009: Ping to server failed
    public class LdapPingFailedException : LdapSetupException
    {
        public LdapPingFailedException(string message)
            : base($"Failed to ping server: {message}", 4009) { }
    }
}
