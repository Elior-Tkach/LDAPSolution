using System;
using System.IO;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LDAP_DLL;

namespace LDAP_DLL.Tests
{
    [TestClass]
    public class SetupTests
    {
        private string _testDir = string.Empty;
        private string _iniPath = string.Empty;

        [TestInitialize]
        public void Init()
        {
            _testDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_testDir);

            // Use reflection to override the GetIniPath method for testing
            typeof(Setup)
                .GetField("<>c__DisplayClass0_0", BindingFlags.NonPublic | BindingFlags.Static)?
                .SetValue(null, null);

            // Copy the executing assembly to the test directory to simulate the DLL location
            var dllPath = Assembly.GetExecutingAssembly().Location;
            var destDllPath = Path.Combine(_testDir, Path.GetFileName(dllPath));
            File.Copy(dllPath, destDllPath, true);

            // Set the current directory to the test directory
            Directory.SetCurrentDirectory(_testDir);

            _iniPath = Path.Combine(_testDir, "LDAP.ini");
        }

        [TestCleanup]
        public void Cleanup()
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
            if (Directory.Exists(_testDir))
                Directory.Delete(_testDir, true);
        }

        [TestMethod]
        public void RecordLdapServerDetailsSimple_CreatesIniFile()
        {
            string error;
            var result = Setup.RecordLdapServerDetailsSimple("localhost", "testuser", out error);

            Assert.IsTrue(result, "Should return true on success");
            Assert.IsTrue(File.Exists(_iniPath), "INI file should be created");
            var content = File.ReadAllText(_iniPath);
            Assert.IsTrue(content.Contains("Host=localhost"), "Header should contain host");
            Assert.IsNull(error, "Error should be null");
        }

        [TestMethod]
        public void RecordLdapUserDetailsSimple_AppendsUserEntry()
        {
            string error;
            Setup.RecordLdapServerDetailsSimple("localhost", "testuser", out error);
            var result = Setup.RecordLdapUserDetailsSimple("jdoe", "John Doe", "jdoe@example.com", out error);

            Assert.IsTrue(result, "Should return true on success");
            var content = File.ReadAllText(_iniPath);
            Assert.IsTrue(content.Contains("jdoe,User,O"), "Should contain user entry");
            Assert.IsNull(error, "Error should be null");
        }

        [TestMethod]
        public void MarkUserPermission_UpdatesPermissionType()
        {
            string error;
            Setup.RecordLdapServerDetailsSimple("localhost", "testuser", out error);
            Setup.RecordLdapUserDetailsSimple("jdoe", "John Doe", "jdoe@example.com", out error);

            var result = Setup.MarkUserPermission("jdoe", "A", out error);

            Assert.IsTrue(result, "Should return true on success");
            var content = File.ReadAllText(_iniPath);
            Assert.IsTrue(content.Contains("jdoe,User,A"), "Permission type should be updated to 'A'");
            Assert.IsNull(error, "Error should be null");
        }
    }
}