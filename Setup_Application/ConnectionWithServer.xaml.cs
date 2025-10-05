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
        }

        private void ShowError(string message)
        {
            ErrorTextBox.Text = message;
            bool hasMessage = !string.IsNullOrWhiteSpace(message);
            ErrorTextBox.Visibility = hasMessage ? Visibility.Visible : Visibility.Collapsed;
            ErrorTextBoxBorder.Visibility = hasMessage ? Visibility.Visible : Visibility.Collapsed;
        }

        private void TestConnectionBtn_Click(object sender, RoutedEventArgs e)
        {
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
            var host = HostTextBox.Text;
            var username = UsernameTextBox.Text;
            var password = PasswordTextBox.Password;    
            var response = LDAP_Setup.TestLdapCredentials(host,username,password);
            if (response.Success)
            {
                CredentialsValidated?.Invoke(host, username, password);
            }
            else
            {
                ShowError(response.ErrorMessage);
            }

        }

        private void InputFieldsChanged(object sender, RoutedEventArgs e)
        {
            ContinueBtn.IsEnabled =
                !string.IsNullOrWhiteSpace(HostTextBox.Text) &&
                !string.IsNullOrWhiteSpace(UsernameTextBox.Text) &&
                !string.IsNullOrWhiteSpace(PasswordTextBox.Password);
        }

        private void ShowStatusIcon(bool success)
        {
            StatusIcon.Source = new BitmapImage(new Uri(success ? "success.png" : "error.png", UriKind.Relative));
            StatusIcon.Visibility = Visibility.Visible;
        }
    }
}
