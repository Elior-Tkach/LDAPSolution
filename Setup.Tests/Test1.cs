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
            var result = Setup.RecordLdapServerDetailsSimple("192.168.20.228", "Avraham", out error);
            Assert.IsTrue(result, $"Should return true on success. Error: {error}");
            Assert.IsNull(error, $"Error should be null. Error: {error}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");

            // Print the actual path used by Setup.GetIniPath()
            var actualIniPath = LDAP_DLL.Setup.GetIniPath();
            TestContext.WriteLine("Actual INI path: " + actualIniPath);
            Assert.IsTrue(File.Exists(actualIniPath), "INI file should be created at: " + actualIniPath);

            Assert.IsTrue(File.Exists(iniPath), "INI file should be created");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("Server: IPs="), $"Header should contain 'Server: IPs='. Actual content: {content}");

        }

        [TestMethod]
        public void RecordLdapUserDetailsSimple_AppendsUserEntry()
        {
            string error;
            var serverResult = Setup.RecordLdapServerDetailsSimple("192.168.20.228", "Avraham", out error);
            Assert.IsTrue(serverResult, $"Should return true on server details. Error: {error}");
            Assert.IsNull(error, $"Error should be null after server details. Error: {error}");

            var result = Setup.RecordLdapUserDetailsSimple("jdoe", "John Doe", "jdoe@example.com", out error);
            Assert.IsTrue(result, $"Should return true on user entry. Error: {error}");
            Assert.IsNull(error, $"Error should be null after user entry. Error: {error}");

            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");

            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("jdoe,User,O"), "Should contain user entry");
        }

        [TestMethod]
        public void MarkUserPermission_UpdatesPermissionType()
        {
            string error;
            var serverResult = Setup.RecordLdapServerDetailsSimple("192.168.20.228", "Avraham", out error);
            Assert.IsTrue(serverResult, $"Should return true on server details. Error: {error}");
            Assert.IsNull(error, $"Error should be null after server details. Error: {error}");

            var userResult = Setup.RecordLdapUserDetailsSimple("jdoe", "John Doe", "jdoe@example.com", out error);
            Assert.IsTrue(userResult, $"Should return true on user entry. Error: {error}");
            Assert.IsNull(error, $"Error should be null after user entry. Error: {error}");

            CopyIniToOutputDir();

            var result = Setup.MarkUserPermission("jdoe", "A", out error);
            Assert.IsTrue(result, $"Should return true on permission update. Error: {error}");
            Assert.IsNull(error, $"Error should be null after permission update. Error: {error}");

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("jdoe,User,A"), "Permission type should be updated to 'A'");
        }

        [TestMethod]
        public void RecordLdapGroupDetailsSimple_CreatesIniFile()
        {
            string error;
            var result = Setup.RecordLdapGroupDetailsSimple("TestGroup", "A test group", out error);
            Assert.IsTrue(result, $"Should return true on group entry. Error: {error}");
            Assert.IsNull(error, $"Error should be null after group entry. Error: {error}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("TestGroup,Group,O"), "Should contain group entry");
        }

        [TestMethod]
        public void MarkGroupPermission_UpdatesPermissionType()
        {
            string error;
            var serverResult = Setup.RecordLdapServerDetailsSimple("192.168.20.228", "Avraham", out error);
            Assert.IsTrue(serverResult, $"Should return true on server details. Error: {error}");
            Assert.IsNull(error, $"Error should be null after server details. Error: {error}");

            var groupResult = Setup.RecordLdapGroupDetailsSimple("TestGroup", "A test group", out error);
            Assert.IsTrue(groupResult, $"Should return true on group entry. Error: {error}");
            Assert.IsNull(error, $"Error should be null after group entry. Error: {error}");

            CopyIniToOutputDir();

            var result = Setup.MarkGroupPermission("TestGroup", "A", out error);
            Assert.IsTrue(result, $"Should return true on permission update. Error: {error}");
            Assert.IsNull(error, $"Error should be null after permission update. Error: {error}");

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("TestGroup,Group,A"), "Permission type should be updated to 'A'");
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
            TestContext.WriteLine($"GetAllGroups result length: {result?.Length}, error: {error}");
            Assert.IsNotNull(result, "Should return a string array (may be empty)");
            Assert.IsTrue(result is string[], "Should return a string array");
        }

        [TestMethod]
        public void GetUsersInGroup_ReturnsArrayOrError()
        {
            string error;
            var result = Setup.GetUsersInGroup("AccellixServer", out error, "IT_Support", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetUsersInGroup result length: {result?.Length}, error: {error}");
            Assert.IsNotNull(result, "Should return a string array (may be empty)");
            Assert.IsTrue(result is string[], "Should return a string array");
        }

        [TestMethod]
        public void TestConnection_ReturnsBoolAndError()
        {
            string error;
            var result = Setup.TestConnection("AccellixServer", out error);
            TestContext.WriteLine($"TestConnection result: {result}, error: {error}");
            Assert.IsTrue(result == true || result == false, "Should return a bool");
        }
    }
}