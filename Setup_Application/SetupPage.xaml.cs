using System.Windows;
using LDAP_DLL;

namespace Setup_Application
{
    public partial class SetupPage : Window
    {
        private string selectedName = "";
        private string selectedType = "U"; // U=user, G=group

        public SetupPage()
        {
            InitializeComponent();
        }

        private void FindUserBtn_Click(object sender, RoutedEventArgs e)
        {
            // Call LDAP functions here (mock for now)
            ResultsListBox.Items.Clear();
            ResultsListBox.Items.Add("Mike Rubin (mrubin)");
            ResultsListBox.Items.Add("Mike Levi (mlevi)");
            ResultsListBox.Items.Add("Mike Dudu (mdudu)");
        }

        private void FindGroupBtn_Click(object sender, RoutedEventArgs e)
        {
            // Mock example
            ResultsListBox.Items.Clear();
            ResultsListBox.Items.Add("Admins");
            ResultsListBox.Items.Add("Operators");
            selectedType = "G";
        }

        private void ClearAllBtn_Click(object sender, RoutedEventArgs e)
        {
            LDAP_Setup.ClearLdapPermissions();
            ResultsListBox.Items.Clear();
            SelectedTextBox.Text = "";
        }

        private void SaveBtn_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(selectedName))
            {
                MessageBox.Show("Select a user or group first.");
                return;
            }

            string permission = OperatorRadio.IsChecked == true ? "O" : "A";
            var response = LDAP_Setup.SaveLdapPermission(selectedName, selectedType, permission);

            if (response.Success)
                MessageBox.Show("Permission saved successfully.");
            else
                MessageBox.Show("Error: " + response.ErrorMessage);
        }
    }
}
