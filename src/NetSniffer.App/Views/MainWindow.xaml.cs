using Wpf.Ui.Controls;

namespace NetSniffer.App.Views;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        Closed += (_, _) =>
        {
            PacketsPage.ViewModel.Dispose();
            ProxyPageControl.ViewModel.Dispose();
        };

        // Set the initial nav selection here, not via IsChecked="True" in XAML: a RadioButton
        // raises Checked synchronously as soon as its IsChecked is set, which during XAML parsing
        // happens before later sibling elements (PacketsPage/ProxyPageControl) are constructed -
        // the handler would run against still-null fields and crash startup.
        PacketsNavButton.IsChecked = true;
    }

    private void OnPacketsNavChecked(object sender, System.Windows.RoutedEventArgs e)
    {
        if (PacketsPage is null || ProxyPageControl is null) return;
        PacketsPage.Visibility = System.Windows.Visibility.Visible;
        ProxyPageControl.Visibility = System.Windows.Visibility.Collapsed;
    }

    private void OnProxyNavChecked(object sender, System.Windows.RoutedEventArgs e)
    {
        if (PacketsPage is null || ProxyPageControl is null) return;
        PacketsPage.Visibility = System.Windows.Visibility.Collapsed;
        ProxyPageControl.Visibility = System.Windows.Visibility.Visible;
    }
}
