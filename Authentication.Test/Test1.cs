using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LDAP_DLL;

namespace LDAP_DLL.Tests
{
    [TestClass]
    public class AuthenticationTests
    {
        private string _iniPath;
        public TestContext TestContext { get; set; } // Add this property

        [TestInitialize]
        public void Init()
        {
            // Setup a temp INI file for each test
            var testDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(testDir);
            Directory.SetCurrentDirectory(testDir);
            _iniPath = Path.Combine(testDir, "LDAP.ini");

            // Use Setup methods to create the INI file and add entries
            LDAP_Setup.RecordLdapServerDetailsSimple("AccellixServer");
            LDAP_Setup.SaveLdapPermission("jdoe", "U", "A");
            LDAP_Setup.SaveLdapPermission("Engineering", "G", "O");
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (File.Exists(_iniPath))
                File.Delete(_iniPath);
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
        }

        [TestMethod]
        public void IsUserRegistered_ReturnsTrue_WhenUserExistsWithPermission()
        {
            string error;
            var result = LDAP_Authentication.IsUserRegistered("jdoe", "A");
            Assert.IsTrue(result, "Should return true for user with correct permission");
        }

        [TestMethod]
        public void IsUserRegistered_ReturnsFalse_WhenUserDoesNotExist()
        {
            string error;
            var result = LDAP_Authentication.IsUserRegistered("notfound", "A");
            Assert.IsFalse(result, "Should return false for non-existent user");
        }

        [TestMethod]
        public void IsUserRegistered_ReturnsFalse_WhenPermissionDoesNotMatch()
        {
            var result = LDAP_Authentication.IsUserRegistered("jdoe", "O");
            Assert.IsFalse(result, "Should return false for user with wrong permission");
        }

        [TestMethod]
        public void IsUserInRegisteredGroup_ReturnsTrue_WhenGroupExistsWithPermission()
        {
            string error;
            var result = LDAP_Authentication.IsUserInRegisteredGroup("Avraham", "Avraham", "Acx2020", "O");
            Assert.IsTrue(result, "Should return true for group with correct permission");
        }

        [TestMethod]
        public void AuthenticateUser_ReturnsFalse_WhenUserAndGroupNotFound()
        {
            var response = LDAP_Authentication.AuthenticateUser("Avraham", "Acx2020", "A");
            Assert.IsFalse(response.ResultBool, "Should return false for non-existent user");
            Assert.IsFalse(response.Success, "Operation should not be successful for non-existent user");
            Assert.IsFalse(string.IsNullOrEmpty(response.ErrorMessage), "Error should not be null or empty when authentication fails");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
        }

        [TestMethod]
        public void GetGroupsForUserArray_ReturnsGroups_WhenUserExists()
        {
            // Arrange
            string ldapPath = "fe80::c896:5f71:35aa:3443%17"; // Use your actual LDAP path or server
            string userName = "Avraham"; // The sAMAccountName of the user
            string username = "Avraham"; // LDAP bind username (may need DOMAIN\\username)
            string password = "Acx2020"; // LDAP bind password

            // Act
            var groups = LDAP_DLL.LDAP_Functions.GetGroupsForUserArray(ldapPath, userName, username, password);
            Assert.IsNotNull(groups, "Groups array should not be null");
            Assert.IsTrue(groups.Length > 0, "User should belong to at least one group");
            TestContext.WriteLine("Groups: " + string.Join(", ", groups)); // Use instance property
        }
    }
}
