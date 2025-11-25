using LDAP_DLL;
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;

namespace Setup_Application
{
    public partial class ConnectionWithServer : UserControl

    {

        public event Action<string, string, string> CredentialsValidated;


        public ConnectionWithServer()
        {
            InitializeComponent();

            // Load IP from LDAP.ini if it exists and prefill the HostTextBox
            try
            {
                string iniPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LDAP.ini");
                if (System.IO.File.Exists(iniPath))
                {
                    var lines = System.IO.File.ReadAllLines(iniPath);
                    foreach (var line in lines)
                    {
                        // Look for the server line with IP
                        if (line.StartsWith("Server: IP="))
                        {
                            var IPPart = line.Split(',')[0];
                            var IPEq = IPPart.IndexOf("IP=");
                            if (IPEq >=0)
                            {
                                // Extract the IP value and prefill the textbox
                                string ip = IPPart.Substring(IPEq +3).Trim('=', ' ');
                                HostTextBox.Text = ip;
                                break;
                            }
                        }
                    }
                }
            }
            catch { /* Ignore errors, just don't prefill */ }
        }

        private void ShowError(string message)
        {
            // Show or hide the error message UI
            ErrorTextBox.Text = message;
            bool hasMessage = !string.IsNullOrWhiteSpace(message);
            ErrorTextBox.Visibility = hasMessage ? Visibility.Visible : Visibility.Collapsed;
            ErrorTextBoxBorder.Visibility = hasMessage ? Visibility.Visible : Visibility.Collapsed;
        }

        private void TestConnectionBtn_Click(object sender, RoutedEventArgs e)
        {
            // Test connection to the LDAP server using the provided host
            var host = HostTextBox.Text;
            var response = LDAP_Setup.TestConnection(host);
            if (response.Success)
            {
                ShowError("Connection successful");
                ShowStatusIcon(true);
            }
            else
            {
                ShowError(response.ErrorMessage);
                ShowStatusIcon(false);
            }
        }

        private void SaveServerBtn_Click(object sender, RoutedEventArgs e)
        {
            // Save the server details to LDAP.ini
            var host = HostTextBox.Text;
            var response = LDAP_Setup.RecordLdapServerDetailsSimple(host);
            if (response.Success)
            {
                ShowError("Server saved successfully");
                ShowStatusIcon(true);
            }
            else
            {
                ShowError(response.ErrorMessage);
                ShowStatusIcon(false);
            }
        }

        private void ContinueBtn_Click(object sender, RoutedEventArgs e)
        {
            // Ensure the server is saved before continuing
            if (!LDAP_Setup.IsServerRecorded())
            {
                ShowError("Save the server before continue");
                return;
            }
            // Validate credentials by attempting to bind to LDAP
            var host = HostTextBox.Text;
            var username = UsernameTextBox.Text;
            var password = PasswordTextBox.Password;    
            var response = LDAP_Setup.TestLdapCredentials(host,username,password);
            if (response.Success)
            {
                // Raise event if credentials are valid
                CredentialsValidated?.Invoke(host, username, password);
            }
            else
            {
                ShowError(response.ErrorMessage);
            }

        }

        private void InputFieldsChanged(object sender, RoutedEventArgs e)
        {
            // Enable the Continue button only if all fields are filled
            bool allFilled = 
                !string.IsNullOrWhiteSpace(HostTextBox.Text) &&
                !string.IsNullOrWhiteSpace(UsernameTextBox.Text) &&
                !string.IsNullOrWhiteSpace(PasswordTextBox.Password);

            ContinueBtn.IsEnabled = allFilled;
        }

        private void ShowStatusIcon(bool success)
        {
            // Show a status icon (success or error) based on the operation result
            StatusIcon.Source = new BitmapImage(new Uri(success ? "success.png" : "error.png", UriKind.Relative));
            StatusIcon.Visibility = Visibility.Visible;
        }
    }
}
