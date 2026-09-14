using System.Windows.Controls;
using NetSniffer.App.ViewModels;

namespace NetSniffer.App.Views;

public partial class ProxyPage : UserControl
{
    public ProxyViewModel ViewModel { get; } = new();

    public ProxyPage()
    {
        InitializeComponent();
        DataContext = ViewModel;
    }
}
