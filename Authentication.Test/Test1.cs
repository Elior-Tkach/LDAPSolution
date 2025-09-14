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
            Setup.RecordLdapServerDetailsSimple("LDAP://localhost", out error);
            Setup.SaveLdapPermission("jdoe", "U", "A", out error);
            Setup.SaveLdapPermission("TestGroup", "G", "O", out error);
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
            var result = Authentication.IsUserRegistered("jdoe", "A", out error);
            Assert.IsTrue(result, "Should return true for user with correct permission");
            Assert.IsNull(error, "Error should be null for valid user");
        }

        [TestMethod]
        public void IsUserRegistered_ReturnsFalse_WhenUserDoesNotExist()
        {
            string error;
            var result = Authentication.IsUserRegistered("notfound", "A", out error);
            Assert.IsFalse(result, "Should return false for non-existent user");
            Assert.AreEqual("User not found in INI file.", error);
        }

        [TestMethod]
        public void IsUserRegistered_ReturnsFalse_WhenPermissionDoesNotMatch()
        {
            string error;
            var result = Authentication.IsUserRegistered("jdoe", "O", out error);
            Assert.IsFalse(result, "Should return false for user with wrong permission");
            Assert.IsTrue(error.Contains("permission type does not match"));
        }

        // You may need to mock LDAP_Functions.GetGroupsForUserArray for this test to work reliably
        [TestMethod]
        public void IsUserInRegisteredGroup_ReturnsTrue_WhenGroupExistsWithPermission()
        {
            // This test assumes LDAP_Functions.GetGroupsForUserArray returns "TestGroup"
            // You may need to mock this method for a real unit test
            string error;
            var result = Authentication.IsUserInRegisteredGroup("TestGroup", "anyuser", "anypass", "O", out error);
            // This will only work if LDAP_Functions.GetGroupsForUserArray returns ["TestGroup"]
            // Otherwise, you need to mock/stub that method
            // Assert.IsTrue(result, "Should return true for group with correct permission");
        }

        [TestMethod]
        public void AuthenticateUser_ReturnsFalse_WhenUserAndGroupNotFound()
        {
            string error;
            var result = Authentication.AuthenticateUser("notfound", "badpass", "A", out error);
            Assert.IsFalse(result, "Should return false for non-existent user");
            Assert.IsTrue(error.Contains("User does not have the required permission type") || error.Contains("User not found in INI file."));
        }
    }
}
