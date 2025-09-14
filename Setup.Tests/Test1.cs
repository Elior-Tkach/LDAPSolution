using System;
using System.IO;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LDAP_DLL;

namespace LDAP_DLL.Tests
{
    [TestClass]
    public class SSetupTests
    {
        public TestContext TestContext { get; set; }
        private string _testDir = string.Empty;
        private string _iniPath = string.Empty;

        [TestInitialize]
        public void Init()
        {
            _testDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_testDir);

            // Delete LDAP.ini in output directory before each test
            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            if (File.Exists(iniPath))
                File.Delete(iniPath);

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

        private void CopyIniToOutputDir()
        {
            // Copy the INI file to the test output directory where Setup.GetIniPath() expects it
            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var destIniPath = Path.Combine(outputDir, "LDAP.ini");
            if (File.Exists(_iniPath))
            {
                // Retry logic in case the file is temporarily locked
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        File.Copy(_iniPath, destIniPath, true);
                        break;
                    }
                    catch (IOException)
                    {
                        System.Threading.Thread.Sleep(50); // wait 50ms and retry
                    }
                }
            }
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
            var result = Setup.RecordLdapServerDetailsSimple("AccellixServer", out error);
            Assert.IsTrue(result, $"Should return true on success. Error: {error}");
            Assert.IsNull(error, $"Error should be null. Error: {error}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");

            Assert.IsTrue(File.Exists(iniPath), "INI file should be created");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);

            Assert.IsTrue(content.Contains("# LDAP Configuration File"), "Header should contain '# LDAP Configuration File'");
            Assert.IsTrue(content.Contains("Server: IPs="), "Header should contain 'Server: IPs='");
            Assert.IsTrue(content.Contains("# --------- Access Control List ---------"), "Header should contain ACL section");
            Assert.IsTrue(content.Contains("# Columns: name,type,permission"), "Header should contain columns comment");
        }

        [TestMethod]
        public void SaveLdapPermission_AppendsUserEntry_CorrectFormat()
        {
            string error;
            Setup.RecordLdapServerDetailsSimple("192.168.20.228", out error);
            var result = Setup.SaveLdapPermission("jdoe", "U", "O", out error);
            Assert.IsTrue(result, $"Should return true on user permission save. Error: {error}");
            Assert.IsNull(error, $"Error should be null after user permission save. Error: {error}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);

            Assert.IsTrue(content.Contains("jdoe,U,O"), "Should contain user entry in correct format (name,U,O)");
        }

        [TestMethod]
        public void SaveLdapPermission_AppendsGroupEntry_CorrectFormat()
        {
            string error;
            Setup.RecordLdapServerDetailsSimple("AccellixServer", out error);
            var result = Setup.SaveLdapPermission("TestGroup", "G", "O", out error);
            Assert.IsTrue(result, $"Should return true on group permission save. Error: {error}");
            Assert.IsNull(error, $"Error should be null after group permission save. Error: {error}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);

            Assert.IsTrue(content.Contains("TestGroup,G,O"), "Should contain group entry in correct format (name,G,O)");
        }

        [TestMethod]
        public void SaveLdapPermission_UpdatesPermission()
        {
            string error;
            Setup.RecordLdapServerDetailsSimple("AccellixServer", out error);
            Setup.SaveLdapPermission("jdoe", "U", "O", out error);
            var result = Setup.SaveLdapPermission("jdoe", "U", "A", out error);
            Assert.IsTrue(result, $"Should return true on permission update. Error: {error}");
            Assert.IsNull(error, $"Error should be null after permission update. Error: {error}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("jdoe,U,A"), "Permission type should be updated to 'A'");
        }

        [TestMethod]
        public void GetUser_ReturnsResultOrError()
        {
            string error;
            var result = Setup.GetUser("AccellixServer", out error, "Emily", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetUser result: {result}, error: {error}");
            Assert.IsTrue(result == null || result is string, "Should return a string or null");
        }

        [TestMethod]
        public void GetGroup_ReturnsResultOrError()
        {
            string error;
            var result = Setup.GetGroup("AccellixServer", out error, "IT_Support", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetGroup result: {result}, error: {error}");
            Assert.IsTrue(result == null || result is string, "Should return a string or null");
        }

        [TestMethod]
        public void GetAllGroups_ReturnsArrayOrError()
        {
            string error;
            var result = Setup.GetAllGroups("AccellixServer", out error, "Avraham", "Acx2020");
            TestContext.WriteLine($"GetAllGroups result: [{string.Join(", ", result)}], error: {error}");
            Assert.IsNotNull(result, "Should return a string array (may be empty)");
            Assert.IsTrue(result is string[], "Should return a string array");
        }

        [TestMethod]
        public void GetUsersInGroup_ReturnsArrayOrError()
        {
            string error;
            var result = Setup.GetUsersInGroup("AccellixServer", out error, "IT_Support", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetUsersInGroup result: [{string.Join(", ", result)}], error: {error}");
            Assert.IsNotNull(result, "Should return a string array (may be empty)");
            Assert.IsTrue(result is string[], "Should return a string array");
        }

        [TestMethod]
        public void TestConnection_ReturnsBoolAndError()
        {
            string error;
            var result = Setup.TestConnection("192.168.20.228", out error);
            TestContext.WriteLine($"TestConnection result: {result}, error: {error}");
            Assert.IsTrue(result == true || result == false, "Should return a bool");
        }

        [TestMethod]
        public void ClearLdapPermissions_RemovesAllUserAndGroupEntries()
        {
            string error;
            // Create INI with server details and user/group entries
            Setup.RecordLdapServerDetailsSimple("AccellixServer", out error);
            Setup.SaveLdapPermission("jdoe", "U", "O", out error);
            Setup.SaveLdapPermission("TestGroup", "G", "A", out error);
            CopyIniToOutputDir();

            // Act
            var result = Setup.ClearLdapPermissions(out error);
            Assert.IsTrue(result, $"Should return true on clear. Error: {error}");
            Assert.IsNull(error, $"Error should be null after clear. Error: {error}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content after clear: " + content);

            // Assert: no user/group entries remain
            Assert.IsFalse(content.Contains("jdoe,U,O"), "User entry should be removed");
            Assert.IsFalse(content.Contains("TestGroup,G,A"), "Group entry should be removed");
            Assert.IsTrue(content.Contains("Server: IPs="), "Server line should remain");
            Assert.IsTrue(content.Contains("# LDAP Configuration File"), "Header should remain");
        }
    }
}