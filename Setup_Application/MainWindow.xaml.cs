using System.Windows;
using System.Windows.Controls;

namespace Setup_Application
{
    public partial class MainWindow : Window
    {
    public MainWindow()
        {
            InitializeComponent();
            // Reference the ConnectionWithServer control directly by name
            connectionControl.CredentialsValidated += OnCredentialsValidated;
        }

        private void OnCredentialsValidated(string host, string username, string password)
        {
            // Only add Setup tab if not already present
            if (MainTabControl.Items.Count < 2)
            {
                var setupControl = new SetupPage(host, username, password);
                var setupTab = new TabItem
                {
                    Header = "Setup",
                    Content = setupControl
                };
                MainTabControl.Items.Add(setupTab);
            }
            MainTabControl.SelectedIndex = 1; // Switch to Setup tab
        }

        private void ConnectionWithServer_Loaded(object sender, RoutedEventArgs e)
        {

        }
    }
}
