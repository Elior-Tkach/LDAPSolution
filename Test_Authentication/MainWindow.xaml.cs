using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using LDAP_DLL;

namespace Test_Authentication
{
    public partial class AuthenticateUserWindow : Window
    {
        public AuthenticateUserWindow()
        {
            InitializeComponent();
        }

        private void Authenticate_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameBox.Text;
            string password = PasswordBox.Password;
            string permission = PermissionBox.Text;

            var response = LDAP_Authentication.AuthenticateUser(username, password, permission);

            // Print the LdapResponse as a string
            ResultBlock.Text = $"Success: {response.Success}\n" +
                               $"ErrorNumber: {response.ErrorNumber}\n" +
                               $"ErrorMessage: {response.ErrorMessage}\n" +
                               $"ResultString: {response.ResultString}\n" +
                               $"ResultArray: {(response.ResultArray != null ? string.Join(", ", response.ResultArray) : "null")}";
        }
    }
}
