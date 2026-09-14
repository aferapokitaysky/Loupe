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
    }

    private void OnPacketsNavChecked(object sender, System.Windows.RoutedEventArgs e)
    {
        PacketsPage.Visibility = System.Windows.Visibility.Visible;
        ProxyPageControl.Visibility = System.Windows.Visibility.Collapsed;
    }

    private void OnProxyNavChecked(object sender, System.Windows.RoutedEventArgs e)
    {
        PacketsPage.Visibility = System.Windows.Visibility.Collapsed;
        ProxyPageControl.Visibility = System.Windows.Visibility.Visible;
    }
}
