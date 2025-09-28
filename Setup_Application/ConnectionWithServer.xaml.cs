using System.Windows;
using LDAP_DLL;

namespace Setup_Application
{
    public partial class ConnectionWithServer : Window
    {
        public ConnectionWithServer()
        {
            InitializeComponent();
        }

        private void TestConnectionBtn_Click(object sender, RoutedEventArgs e)
        {
            var host = HostTextBox.Text;
            var response = LDAP_Setup.TestConnection(host);
            if (response.Success)
            {
                ErrorTextBox.Text = "Connection successful";
            }
            else
            {
                ErrorTextBox.Text = response.ErrorMessage;
            }
        }

        private void SaveServerBtn_Click(object sender, RoutedEventArgs e)
        {
            var host = HostTextBox.Text;
            var response = LDAP_Setup.RecordLdapServerDetailsSimple(host);
            if (response.Success)
            {
                ErrorTextBox.Text = "Server saved successfully";
            }
            else
            {
                ErrorTextBox.Text = response.ErrorMessage;
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
                var setupPage = new SetupPage(host, username, password);
                setupPage.Show();
                this.Close();
            }
            else
            {
                ErrorTextBox.Text = response.ErrorMessage;
            }

        }
    }
}
