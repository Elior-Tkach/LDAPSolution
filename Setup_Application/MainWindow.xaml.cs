using System.Windows;
using System.Windows.Controls;

namespace Setup_Application
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            var connectionControl = (ConnectionWithServer)((TabItem)MainTabControl.Items[0]).Content;
            connectionControl.CredentialsValidated += OnCredentialsValidated;
        }

        private void OnCredentialsValidated(string host, string username, string password)
        {
            // Only add Setup tab if not already present
            if (MainTabControl.Items.Count < 2)
            {
                var setupControl = new SetupPage(host,username,password);
                // Optionally pass host, username, password to setupControl via properties or constructor
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
