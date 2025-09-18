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
            string error;
            LDAP_Setup.RecordLdapServerDetailsSimple("AccellixServer", out error);
            LDAP_Setup.SaveLdapPermission("jdoe", "U", "A", out error);
            LDAP_Setup.SaveLdapPermission("Engineering", "G", "O", out error);
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
            var result = LDAP_Authentication.IsUserRegistered("jdoe", "A", out error);
            Assert.IsTrue(result, "Should return true for user with correct permission");
            Assert.IsNull(error, "Error should be null for valid user");
        }

        [TestMethod]
        public void IsUserRegistered_ReturnsFalse_WhenUserDoesNotExist()

        {
            string error;
            var result = LDAP_Authentication.IsUserRegistered("notfound", "A", out error);
            Assert.IsFalse(result, "Should return false for non-existent user");
            Assert.AreEqual("User not found in INI file.", error);
        }

        [TestMethod]
        public void IsUserRegistered_ReturnsFalse_WhenPermissionDoesNotMatch()
        {
            string error;
            var result = LDAP_Authentication.IsUserRegistered("jdoe", "O", out error);
            Assert.IsFalse(result, "Should return false for user with wrong permission");
            Assert.IsTrue(error.Contains("permission type does not match"));
        }

        // You may need to mock LDAP_Functions.GetGroupsForUserArray for this test to work reliably
        [TestMethod]
        public void IsUserInRegisteredGroup_ReturnsTrue_WhenGroupExistsWithPermission()
        {
            string error;
            var result = LDAP_Authentication.IsUserInRegisteredGroup("emiller", "Avraham", "Acx2020", "O", out error);
            Assert.IsTrue(result, "Should return true for group with correct permission");
        }

        [TestMethod]
        public void AuthenticateUser_ReturnsFalse_WhenUserAndGroupNotFound()
        {
            string error;
            var result = LDAP_Authentication.AuthenticateUser("Avraham", "Acx2020", "A", out error);
            Assert.IsFalse(result, "Should return false for non-existent user");
            Assert.IsNotNull(error, "Error should not be null when authentication fails");
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
            string error;
            var groups = LDAP_DLL.LDAP_Functions.GetGroupsForUserArray(ldapPath, out error, userName, username, password);

            // Assert
            if (!string.IsNullOrEmpty(error))
            {
                Assert.Fail("LDAP error: " + error);
            }
            Assert.IsNotNull(groups, "Groups array should not be null");
            Assert.IsTrue(groups.Length > 0, "User should belong to at least one group");
            TestContext.WriteLine("Groups: " + string.Join(", ", groups)); // Use instance property
        }
    }
}
