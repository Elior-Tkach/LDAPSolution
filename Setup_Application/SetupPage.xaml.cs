using LDAP_DLL;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Collections.Generic;
using System.Linq; // Add this at the top with other using directives

namespace Setup_Application
{
    public partial class SetupPage : UserControl
    {
        private readonly string host;
        private readonly string username;
        private readonly string password;
        private string selectedName = "";
        private string selectedType = "U"; // U=user, G=group

        // Add a mode flag to distinguish between group search and user-in-group search
        private enum GroupInputMode { None, FindGroup, UsersInGroup }
        private GroupInputMode groupInputMode = GroupInputMode.None;

        private Button _lastHighlightedButton;

        public class TreeNodeData
        {
            public string Name { get; set; }
            public string TypeLabel { get; set; }
            public List<TreeNodeData> Children { get; set; } = new List<TreeNodeData>();
        }


        public SetupPage(string host, string username, string password)
        {
            InitializeComponent();
            this.host = host;
            this.username = username;
            this.password = password;

            UserSelectListBox.SelectionChanged += UserSelectListBox_SelectionChanged;
            OperatorRadio.Checked += PermissionRadio_Checked;
            AdminRadio.Checked += PermissionRadio_Checked;
            GroupTreeView.SelectedItemChanged += GroupTreeView_SelectedItemChanged;
        }

        private void HideAllDynamicControls()
        {
            UserNamePromptTextBlock.Visibility = Visibility.Collapsed;
            UserNameInputTextBox.Visibility = Visibility.Collapsed;
            GroupNamePromptTextBlock.Visibility = Visibility.Collapsed;
            GroupNameInputTextBox.Visibility = Visibility.Collapsed;
            GroupTreeView.Visibility = Visibility.Collapsed;
        }

        private void HidePermissionControls()
        {
            OperatorRadio.Visibility = Visibility.Collapsed;
            AdminRadio.Visibility = Visibility.Collapsed;
            SaveBtn.Visibility = Visibility.Collapsed;
        }

        private void HideAllTextAndListBoxesAndTextBlocks()
        {
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserNameInputTextBox.Visibility = Visibility.Collapsed;
            GroupNameInputTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;
            PermissionsListBox.Visibility = Visibility.Collapsed;
            UserNamePromptTextBlock.Visibility = Visibility.Collapsed;
            GroupNamePromptTextBlock.Visibility = Visibility.Collapsed;
        }

        private void FindUserBtn_Click(object sender, RoutedEventArgs e)
        {
            Button_Click(sender, e); // Highlight logic
            HideAllDynamicControls();
            UserNamePromptTextBlock.Visibility = Visibility.Visible;
            UserNameInputTextBox.Visibility = Visibility.Visible;
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;
            HidePermissionControls();
        }

        private void FindGroupBtn_Click(object sender, RoutedEventArgs e)
        {
            Button_Click(sender, e); // Highlight logic
            HideAllDynamicControls();
            GroupNamePromptTextBlock.Visibility = Visibility.Visible;
            GroupNameInputTextBox.Visibility = Visibility.Visible;
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;
            GroupNameInputTextBox.Text = string.Empty;
            HidePermissionControls();
            groupInputMode = GroupInputMode.FindGroup;
        }


        private void ChooseGroupFromListBtn_Click(object sender, RoutedEventArgs e)
        {
            Button_Click(sender, e); // Highlight logic
            HideAllDynamicControls();
            SelectedTextBox.Visibility = Visibility.Collapsed;
            UserSelectListBox.Visibility = Visibility.Collapsed;
            GroupTreeView.Items.Clear();
            GroupTreeView.Visibility = Visibility.Collapsed;

            var groupsResponse = LDAP_Setup.GetAllGroups(host, username, password);
            if (!string.IsNullOrEmpty(groupsResponse.ErrorMessage))
            {
                SelectedTextBox.Text = groupsResponse.ErrorMessage;
                SelectedTextBox.Visibility = Visibility.Visible;
                return;
            }

            if (groupsResponse.ResultArray != null && groupsResponse.ResultArray.Length > 0)
            {
                foreach (var groupName in groupsResponse.ResultArray)
                {
                    GroupTreeView.Items.Add(BuildGroupTreeRecursive(groupName));
                }
                GroupTreeView.Visibility = Visibility.Visible;
            }
            else
            {
                GroupTreeView.Items.Clear();
                GroupTreeView.Visibility = Visibility.Visible;
            }
            HidePermissionControls();
        }

             // Recursive helper to build group-member hierarchy
        private TreeNodeData BuildGroupTreeRecursiveData(string groupName)
        {
            var node = new TreeNodeData { Name = groupName, TypeLabel = "(Group)" };
            var membersResponse = LDAP_Setup.GetAllGroupMembers(host, groupName, username, password);

            if (membersResponse.ResultArray != null && membersResponse.ResultArray.Length > 0)
            {
                foreach (var member in membersResponse.ResultArray)
                {
                    var split = member.LastIndexOf(" (");
                    string memberName = split > 0 ? member.Substring(0, split) : member;
                    string memberType = split > 0 ? member.Substring(split + 2, member.Length - split - 3) : "";

                    if (memberType == "Group")
                    {
                        // Recursively build child group and set label
                        var childGroup = BuildGroupTreeRecursiveData(memberName);
                        childGroup.TypeLabel = "(Group)";
                        node.Children.Add(childGroup);
                    }
                    else
                    {
                        node.Children.Add(new TreeNodeData { Name = memberName, TypeLabel = $"({memberType})" });
                    }
                }
            }
            return node;
        }

        private TreeViewItem BuildGroupTreeRecursive(string groupName)
        {
            // Create a StackPanel for custom coloring
            var stackPanel = new StackPanel { Orientation = Orientation.Horizontal };
            stackPanel.Children.Add(new TextBlock { Text = groupName });
            stackPanel.Children.Add(new TextBlock { Text = " " });
            stackPanel.Children.Add(new TextBlock { Text = "(Group)", Foreground = System.Windows.Media.Brushes.Blue, FontWeight = FontWeights.Bold });

            var groupItem = new TreeViewItem { Header = stackPanel };
            var membersResponse = LDAP_Setup.GetAllGroupMembers(host, groupName, username, password);

            if (membersResponse.ResultArray != null && membersResponse.ResultArray.Length >0)
            {
                foreach (var member in membersResponse.ResultArray)
                {
                    var split = member.LastIndexOf(" (");
                    string memberName = split >0 ? member.Substring(0, split) : member;
                    string memberType = split >0 ? member.Substring(split +2, member.Length - split -3) : "";

                    if (memberType == "Group")
                    {
                        groupItem.Items.Add(BuildGroupTreeRecursive(memberName));
                    }
                    else
                    {
                        var userPanel = new StackPanel { Orientation = Orientation.Horizontal };
                        userPanel.Children.Add(new TextBlock { Text = memberName });
                        userPanel.Children.Add(new TextBlock { Text = " " });
                        userPanel.Children.Add(new TextBlock { Text = "(User)", Foreground = System.Windows.Media.Brushes.Green, FontWeight = FontWeights.Bold });
                        groupItem.Items.Add(new TreeViewItem { Header = userPanel });
                    }
                }
            }
            return groupItem;
        }

        private void UserNameInputTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var userName = UserNameInputTextBox.Text;
                if (!string.IsNullOrWhiteSpace(userName))
                {
                    var response = LDAP_Setup.GetUser(host, userName, username, password);
                    if (!string.IsNullOrEmpty(response.ErrorMessage))
                    {
                        SelectedTextBox.Text = response.ErrorMessage;
                        SelectedTextBox.Visibility = Visibility.Visible;
                        UserSelectListBox.Visibility = Visibility.Collapsed;
                        return;
                    }
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
                        if (!string.IsNullOrEmpty(response.ErrorMessage))
                        {
                            SelectedTextBox.Text = response.ErrorMessage;
                            SelectedTextBox.Visibility = Visibility.Visible;
                            UserSelectListBox.Visibility = Visibility.Collapsed;
                            return;
                        }
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
                        if (!string.IsNullOrEmpty(response.ErrorMessage))
                        {
                            SelectedTextBox.Text = response.ErrorMessage;
                            SelectedTextBox.Visibility = Visibility.Visible;
                            UserSelectListBox.Visibility = Visibility.Collapsed;
                            return;
                        }
                        if (response.ResultArray != null && response.ResultArray.Length > 0)
                        {
                            UserSelectListBox.ItemsSource = response.ResultArray;
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
            Button_Click(sender, e); // Highlight logic
            HideAllTextAndListBoxesAndTextBlocks(); // Hide all textboxes, listboxes, and textblocks
            var result = MessageBox.Show("Are you sure you want to delete all users and groups?", "Confirm Clear", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result == MessageBoxResult.Yes)
            {
                var response = LDAP_Setup.ClearLdapPermissions();
                if (!string.IsNullOrEmpty(response.ErrorMessage))
                {
                    SelectedTextBox.Text = response.ErrorMessage;
                    SelectedTextBox.Visibility = Visibility.Visible;
                    return;
                }
                SelectedTextBox.Text = "";
                HideAllDynamicControls();
                HidePermissionControls();
            }
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

            if (!string.IsNullOrEmpty(response.ErrorMessage))
            {
                SelectedTextBox.Text = response.ErrorMessage;
                SelectedTextBox.Visibility = Visibility.Visible;
                MessageBox.Show("Error: " + response.ErrorMessage);
                return;
            }

            if (response.Success)
            {
                SuccessMessageRun.Text = (selectedType == "G" ? "Group" : "User") + " saved successfully";
                SuccessMessageTextBlock.Visibility = Visibility.Visible;
            }
            else
            {
                MessageBox.Show("Error: " + response.ErrorMessage);
            }
        }

        private void GroupNameInputTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {

        }


        private void UserSelectListBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (UserSelectListBox.SelectedItem != null)
            {
                selectedName = UserSelectListBox.SelectedItem.ToString();
                if (groupInputMode == GroupInputMode.FindGroup)
                    selectedType = "G";
                else
                    selectedType = "U";
                OperatorRadio.Visibility = Visibility.Visible;
                AdminRadio.Visibility = Visibility.Visible;
                OperatorRadio.IsChecked = false; // Deselect radio buttons
                AdminRadio.IsChecked = false;
                SaveBtn.Visibility = Visibility.Collapsed; // Hide until permission selected
            }
        }

        private void GroupTreeView_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            var selectedItem = GroupTreeView.SelectedItem;
            if (selectedItem is TreeViewItem tvi && tvi.Header is StackPanel sp)
            {
                // Find the label text (last TextBlock in the StackPanel)
                string typeLabel = null;
                string name = null;
                foreach (var child in sp.Children)
                {
                    if (child is TextBlock tb)
                    {
                        if (tb.Text.StartsWith("("))
                            typeLabel = tb.Text;
                        else if (!string.IsNullOrWhiteSpace(tb.Text) && tb.Text != " ")
                            name = tb.Text;
                    }
                }
                if (typeLabel == "(Group)" || typeLabel == "(User)")
                {
                    selectedName = name;
                    selectedType = typeLabel == "(Group)" ? "G" : "U";
                    OperatorRadio.Visibility = Visibility.Visible;
                    AdminRadio.Visibility = Visibility.Visible;
                    OperatorRadio.IsChecked = false;
                    AdminRadio.IsChecked = false;
                    SaveBtn.Visibility = Visibility.Collapsed;
                }
            }
        }

        private void PermissionRadio_Checked(object sender, RoutedEventArgs e)
        {
            SaveBtn.Visibility = Visibility.Visible;
        }

        private void ShowPermissionsBtn_Click(object sender, RoutedEventArgs e)
        {
            Button_Click(sender, e); // Highlight logic
            HideAllTextAndListBoxesAndTextBlocks(); // Hide all textboxes, listboxes, and textblocks
            GroupTreeView.Visibility = Visibility.Collapsed; // Hide the tree view
            PermissionsListBox.ItemsSource = null;
            PermissionsListBox.Visibility = Visibility.Collapsed;

            // Hide permission controls when showing permissions
            OperatorRadio.Visibility = Visibility.Collapsed;
            AdminRadio.Visibility = Visibility.Collapsed;
            SaveBtn.Visibility = Visibility.Collapsed;

            // Read LDAP.ini and parse permissions
            string iniPath = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "LDAP.ini");
            if (!System.IO.File.Exists(iniPath))
            {
                MessageBox.Show("LDAP.ini file not found.");
                return;
            }

            var lines = System.IO.File.ReadAllLines(iniPath);
            var displayList = new List<string>();
            foreach (var line in lines)
            {
                // Skip comments and section headers
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#") || line.StartsWith("Server:") || line.StartsWith("-"))
                    continue;

                // Only show lines with permission info (e.g., name,type,permission)
                var parts = line.Split(',');
                if (parts.Length == 3)
                {
                    // Format: name,type,permission
                    var name = parts[0].Trim();
                    var type = parts[1].Trim() == "U" ? "User" : "Group";
                    var perm = parts[2].Trim() == "A" ? "Admin" : "Operator";
                    displayList.Add($"{name} ({type}) - {perm}");
                }
            }

            if (displayList.Count > 0)
            {
                PermissionsListBox.ItemsSource = displayList;
                PermissionsListBox.Visibility = Visibility.Visible;
                ClosePermissionsBtn.Visibility = Visibility.Visible;
                DeleteSelectedPermissionBtn.Visibility = Visibility.Visible; // Show delete button
                ClearAllPermissionsBtn.Visibility = Visibility.Visible; // Show clear all button
            }
            else
            {
                MessageBox.Show("No permissions found in LDAP.ini.");
            }
        }

        private void ClosePermissionsBtn_Click(object sender, RoutedEventArgs e)
        {
            PermissionsListBox.Visibility = Visibility.Collapsed;
            ClosePermissionsBtn.Visibility = Visibility.Collapsed;
            DeleteSelectedPermissionBtn.Visibility = Visibility.Collapsed;
            ClearAllPermissionsBtn.Visibility = Visibility.Collapsed;
        }

        private void DeleteSelectedPermissionBtn_Click(object sender, RoutedEventArgs e)
        {
            if (PermissionsListBox.SelectedItem == null)
            {
                MessageBox.Show("Select a user or group to delete.");
                return;
            }

            string selected = PermissionsListBox.SelectedItem.ToString();
            // Extract the name and type from the display string
            var match = System.Text.RegularExpressions.Regex.Match(selected, @"^(.*) \((User|Group)\) - (Admin|Operator)$");
            if (!match.Success)
            {
                MessageBox.Show("Could not parse selected item.");
                return;
            }
            string name = match.Groups[1].Value.Trim();
            string type = match.Groups[2].Value == "User" ? "U" : "G";

            string iniPath = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "LDAP.ini");
            if (!System.IO.File.Exists(iniPath))
            {
                MessageBox.Show("LDAP.ini file not found.");
                return;
            }
            var lines = System.IO.File.ReadAllLines(iniPath).ToList();
            var newLines = lines.Where(line =>
                !(line.Split(',').Length == 3 &&
                  line.Split(',')[0].Trim() == name &&
                  line.Split(',')[1].Trim() == type)
            ).ToList();
            System.IO.File.WriteAllLines(iniPath, newLines);
            ShowPermissionsBtn_Click(null, null); // Refresh list
        }

        private void ClearAllPermissionsBtn_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show("Are you sure you want to delete all users and groups?", "Confirm Clear", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result == MessageBoxResult.Yes)
            {
                string iniPath = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "LDAP.ini");
                if (!System.IO.File.Exists(iniPath))
                {
                    MessageBox.Show("LDAP.ini file not found.");
                    return;
                }
                var lines = System.IO.File.ReadAllLines(iniPath);
                var newLines = lines.Where(line =>
                    string.IsNullOrWhiteSpace(line) ||
                    line.StartsWith("#") ||
                    line.StartsWith("Server:") ||
                    line.StartsWith("-")
                ).ToList();
                System.IO.File.WriteAllLines(iniPath, newLines);
                ShowPermissionsBtn_Click(null, null); // Refresh list
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            SuccessMessageTextBlock.Visibility = Visibility.Collapsed; // Hide success message on any button click

            // Hide permissions controls on any button click
            PermissionsListBox.Visibility = Visibility.Collapsed;
            DeleteSelectedPermissionBtn.Visibility = Visibility.Collapsed;
            ClearAllPermissionsBtn.Visibility = Visibility.Collapsed;
            ClosePermissionsBtn.Visibility = Visibility.Collapsed;

            if (_lastHighlightedButton != null)
                _lastHighlightedButton.Tag = null;

            var clickedButton = sender as Button;
            if (clickedButton != null)
            {
                clickedButton.Tag = "Highlighted";
                _lastHighlightedButton = clickedButton;
            }
        }
    }
}
   
