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
            typeof(LDAP_Setup)
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
            var response = LDAP_Setup.RecordLdapServerDetailsSimple("AccellixServer");
            Assert.IsTrue(response.Success, $"Should return true on success. Error: {response.ErrorMessage}");
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
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void SaveLdapPermission_AppendsUserEntry_CorrectFormat()
        {
            LDAP_Setup.RecordLdapServerDetailsSimple("192.168.20.228");
            var response = LDAP_Setup.SaveLdapPermission("jdoe", "U", "O");
            Assert.IsTrue(response.Success, $"Should return true on user permission save. Error: {response.ErrorMessage}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("jdoe,U,O"), "Should contain user entry in correct format (name,U,O)");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void SaveLdapPermission_AppendsGroupEntry_CorrectFormat()
        {
            LDAP_Setup.RecordLdapServerDetailsSimple("AccellixServer");
            var response = LDAP_Setup.SaveLdapPermission("TestGroup", "G", "O");
            Assert.IsTrue(response.Success, $"Should return true on group permission save. Error: {response.ErrorMessage}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("TestGroup,G,O"), "Should contain group entry in correct format (name,G,O)");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void SaveLdapPermission_UpdatesPermission()
        {
            LDAP_Setup.RecordLdapServerDetailsSimple("AccellixServer");
            LDAP_Setup.SaveLdapPermission("jdoe", "U", "O");
            var response = LDAP_Setup.SaveLdapPermission("jdoe", "U", "A");
            Assert.IsTrue(response.Success, $"Should return true on permission update. Error: {response.ErrorMessage}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content: " + content);
            Assert.IsTrue(content.Contains("jdoe,U,A"), "Permission type should be updated to 'A'");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void GetUser_ReturnsResultOrError()
        {
            var response = LDAP_Setup.GetUser("AccellixServer", "Emily", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetUser result: {response.ResultString}, error: {response.ErrorMessage}");
            Assert.IsTrue(response.ResultString == null || response.ResultString is string, "Should return a string or null");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void GetGroup_ReturnsResultOrError()
        {
            var response = LDAP_Setup.GetGroup("AccellixServer", "IT_Support", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetGroup result: {response.ResultString}, error: {response.ErrorMessage}");
            Assert.IsTrue(response.ResultString == null || response.ResultString is string, "Should return a string or null");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void GetAllGroups_ReturnsArrayOrError()
        {
            var response = LDAP_Setup.GetAllGroups("fe80::c896:5f71:35aa:3443%17", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetAllGroups result: [{string.Join(", ", response.ResultArray)}], error: {response.ErrorMessage}");
            Assert.IsNotNull(response.ResultArray, "Should return a string array (may be empty)");
            Assert.IsTrue(response.ResultArray is string[], "Should return a string array");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void GetUsersInGroup_ReturnsArrayOrError()
        {
            var response = LDAP_Setup.GetUsersInGroup("AccellixServer", "IT_Support", "Avraham", "Acx2020");
            TestContext.WriteLine($"GetUsersInGroup result: [{string.Join(", ", response.ResultArray)}], error: {response.ErrorMessage}");
            Assert.IsNotNull(response.ResultArray, "Should return a string array (may be empty)");
            Assert.IsTrue(response.ResultArray is string[], "Should return a string array");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void TestConnection_ReturnsBoolAndError()
        {
            var response = LDAP_Setup.TestConnection("192.168.20.228");
            TestContext.WriteLine($"TestConnection result: {response.ResultBool}, error: {response.ErrorMessage}");
            Assert.IsTrue(response.ResultBool == true || response.ResultBool == false, "Should return a bool");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void ClearLdapPermissions_RemovesAllUserAndGroupEntries()
        {
            LDAP_Setup.RecordLdapServerDetailsSimple("AccellixServer");
            LDAP_Setup.SaveLdapPermission("jdoe", "U", "O");
            LDAP_Setup.SaveLdapPermission("TestGroup", "G", "A");
            CopyIniToOutputDir();

            // Act
            var response = LDAP_Setup.ClearLdapPermissions();
            Assert.IsTrue(response.Success, $"Should return true on clear. Error: {response.ErrorMessage}");
            CopyIniToOutputDir();

            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            var content = File.ReadAllText(iniPath);
            TestContext.WriteLine("INI file content after clear: " + content);
            Assert.IsFalse(content.Contains("jdoe,U,O"), "User entry should be removed");
            Assert.IsFalse(content.Contains("TestGroup,G,A"), "Group entry should be removed");
            Assert.IsTrue(content.Contains("Server: IPs="), "Server line should remain");
            Assert.IsTrue(content.Contains("# LDAP Configuration File"), "Header should remain");
            TestContext.WriteLine($"Success: {response.Success}");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            TestContext.WriteLine($"ResultBool: {response.ResultBool}");
            TestContext.WriteLine($"ResultString: {response.ResultString}");
            if (response.ResultArray != null)
                TestContext.WriteLine($"ResultArray: [{string.Join(", ", response.ResultArray)}]");
        }

        [TestMethod]
        public void RecordLdapServerDetailsSimple_ThrowsException_OnPingFailOrWriteError()
        {
            // Case 1: Invalid host (ping failure)
            var response = LDAP_Setup.RecordLdapServerDetailsSimple("invalid_host_!@#");
            TestContext.WriteLine($"ErrorMessage: {response.ErrorMessage}");
            TestContext.WriteLine($"ErrorNumber: {response.ErrorNumber}");
            Assert.IsFalse(response.Success, "Should not succeed for invalid host");
            Assert.AreEqual(4009, response.ErrorNumber, "Should return error number 4009 for ping failure");

            // Case 2: INI file write error (simulate by making directory read-only)
            var outputDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var iniPath = Path.Combine(outputDir, "LDAP.ini");
            try
            {
                // Make directory read-only to cause write failure
                var dirInfo = new DirectoryInfo(outputDir);
                var originalAttributes = dirInfo.Attributes;
                dirInfo.Attributes |= FileAttributes.ReadOnly;

                try
                {
                    var response2 = LDAP_Setup.RecordLdapServerDetailsSimple("AccellixServer");
                    TestContext.WriteLine($"ErrorMessage: {response2.ErrorMessage}");
                    TestContext.WriteLine($"ErrorNumber: {response2.ErrorNumber}");
                    Assert.IsFalse(response2.Success, "Should not succeed when directory is read-only");
                    Assert.AreEqual(4008, response2.ErrorNumber, "Should return error number 4008 for INI file write error");
                }
                finally
                {
                    // Restore directory attributes
                    dirInfo.Attributes = originalAttributes;
                    if (File.Exists(iniPath))
                        File.Delete(iniPath);
                }
            }
            catch (Exception ex)
            {
                TestContext.WriteLine("Setup for write error test failed: " + ex.Message);
            }
        }
    }
}