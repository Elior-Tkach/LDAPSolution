using LDAP_DLL;
using System.Windows;
using System.Windows.Input;

namespace Setup_Application
{
    public partial class SetupPage : Window
    {
        private readonly string host;
        private readonly string username;
        private readonly string password;
        private string selectedName = "";
        private string selectedType = "U"; // U=user, G=group

        // Add a mode flag to distinguish between group search and user-in-group search
        private enum GroupInputMode { None, FindGroup, UsersInGroup }
        private GroupInputMode groupInputMode = GroupInputMode.None;

        public SetupPage(string host, string username, string password)
        {
            InitializeComponent();
            this.host = host;
            this.username = username;
            this.password = password;

            // Attach event handlers for selection
            UserSelectListBox.SelectionChanged += UserSelectListBox_SelectionChanged;
            GroupListBox.SelectionChanged += GroupListBox_SelectionChanged;
        }

        private void HideAllDynamicControls()
        {
            UserNamePromptTextBlock.Visibility = Visibility.Collapsed;
            UserNameInputTextBox.Visibility = Visibility.Collapsed;
            GroupNamePromptTextBlock.Visibility = Visibility.Collapsed;
            GroupNameInputTextBox.Visibility = Visibility.Collapsed;
            GroupListBox.Visibility = Visibility.Collapsed;
        }

        private void HidePermissionControls()
        {
            OperatorRadio.Visibility = Visibility.Collapsed;
            AdminRadio.Visibility = Visibility.Collapsed;
            SaveBtn.Visibility = Visibility.Collapsed;
        }

        private void FindUserBtn_Click(object sender, RoutedEventArgs e)
        {
            HideAllDynamicControls();
            UserNamePromptTextBlock.Visibility = Visibility.Visible;
            UserNameInputTextBox.Visibility = Visibility.Visible;
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;
            HidePermissionControls();
        }

        private void FindGroupBtn_Click(object sender, RoutedEventArgs e)
        {
            HideAllDynamicControls();
            GroupNamePromptTextBlock.Visibility = Visibility.Visible;
            GroupNameInputTextBox.Visibility = Visibility.Visible;
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;
            GroupNameInputTextBox.Text = string.Empty;
            HidePermissionControls();
            groupInputMode = GroupInputMode.FindGroup;
        }

        private void ChooseUserFromGroupBtn_Click(object sender, RoutedEventArgs e)
        {
            HideAllDynamicControls();
            GroupNamePromptTextBlock.Visibility = Visibility.Visible;
            GroupNameInputTextBox.Visibility = Visibility.Visible;
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;
            GroupListBox.Visibility = Visibility.Collapsed;
            GroupNameInputTextBox.Text = string.Empty;
            HidePermissionControls();
            groupInputMode = GroupInputMode.UsersInGroup;
        }

        private void ChooseGroupFromListBtn_Click(object sender, RoutedEventArgs e)
        {
            HideAllDynamicControls();
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;

            // Get all groups from LDAP
            var response = LDAP_Setup.GetAllGroups(host, username, password);
            if (response.ResultArray != null && response.ResultArray.Length > 0)
            {
                GroupListBox.ItemsSource = response.ResultArray;
                GroupListBox.Visibility = Visibility.Visible;
            }
            else
            {
                GroupListBox.ItemsSource = null;
                GroupListBox.Visibility = Visibility.Visible;
            }
            HidePermissionControls();
        }

        private void UserNameInputTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var userName = UserNameInputTextBox.Text;
                if (!string.IsNullOrWhiteSpace(userName))
                {
                    var response = LDAP_Setup.GetUser(host, userName, username, password);
                    if (response.ResultArray != null && response.ResultArray.Length > 0)
                    {
                        UserSelectListBox.ItemsSource = response.ResultArray;
                        UserSelectListBox.Visibility = Visibility.Visible;
                        SelectedTextBox.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        UserSelectListBox.Visibility = Visibility.Collapsed;
                        SelectedTextBox.Text = $"User not found: {userName}";
                        SelectedTextBox.Visibility = Visibility.Visible;
                    }
                }
                else
                {
                    UserSelectListBox.Visibility = Visibility.Collapsed;
                    SelectedTextBox.Text = string.Empty;
                    SelectedTextBox.Visibility = Visibility.Visible;
                }
            }
        }

        private void GroupNameInputTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var groupName = GroupNameInputTextBox.Text;
                if (!string.IsNullOrWhiteSpace(groupName))
                {
                    if (groupInputMode == GroupInputMode.UsersInGroup)
                    {
                        var response = LDAP_Setup.GetUsersInGroup(host, groupName, username, password);
                        if (response.ResultArray != null && response.ResultArray.Length > 0)
                        {
                            UserSelectListBox.ItemsSource = response.ResultArray;
                            UserSelectListBox.Visibility = Visibility.Visible;
                            SelectedTextBox.Visibility = Visibility.Collapsed;
                        }
                        else
                        {
                            UserSelectListBox.Visibility = Visibility.Collapsed;
                            SelectedTextBox.Text = $"No users found in group: {groupName}";
                            SelectedTextBox.Visibility = Visibility.Visible;
                        }
                    }
                    else if (groupInputMode == GroupInputMode.FindGroup)
                    {
                        var response = LDAP_Setup.GetGroup(host, groupName, username, password);
                        if (!string.IsNullOrEmpty(response.ResultString))
                        {
                            UserSelectListBox.ItemsSource = new[] { response.ResultString };
                            UserSelectListBox.Visibility = Visibility.Visible;
                            SelectedTextBox.Visibility = Visibility.Collapsed;
                        }
                        else
                        {
                            SelectedTextBox.Text = $"Group not found: {groupName}";
                            SelectedTextBox.Visibility = Visibility.Visible;
                            UserSelectListBox.Visibility = Visibility.Collapsed;
                        }
                    }
                }
                else
                {
                    UserSelectListBox.Visibility = Visibility.Collapsed;
                    SelectedTextBox.Text = string.Empty;
                    SelectedTextBox.Visibility = Visibility.Visible;
                }
            }
        }


        private void ClearAllBtn_Click(object sender, RoutedEventArgs e)
        {
            LDAP_Setup.ClearLdapPermissions();
            SelectedTextBox.Text = "";
            HideAllDynamicControls();
            HidePermissionControls();
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

        private void GroupNameInputTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {

        }

        private void ReturnToPreviousPageBtn_Click(object sender, RoutedEventArgs e)
        {
            var connectionWindow = new ConnectionWithServer();
            connectionWindow.Show();
            this.Close();
        }

        private void UserSelectListBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (UserSelectListBox.SelectedItem != null)
            {
                selectedName = UserSelectListBox.SelectedItem.ToString();
                selectedType = "U";
                OperatorRadio.Visibility = Visibility.Visible;
                AdminRadio.Visibility = Visibility.Visible;
                SaveBtn.Visibility = Visibility.Visible;
            }
        }

        private void GroupListBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (GroupListBox.SelectedItem != null)
            {
                selectedName = GroupListBox.SelectedItem.ToString();
                selectedType = "G";
                OperatorRadio.Visibility = Visibility.Visible;
                AdminRadio.Visibility = Visibility.Visible;
                SaveBtn.Visibility = Visibility.Visible;
            }
        }
    }
}
