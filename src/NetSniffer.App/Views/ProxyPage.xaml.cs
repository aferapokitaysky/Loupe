using System.Windows;
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

    /// <summary>
    /// Picking a request in the domain tree selects it in the grid and the detail pane below.
    /// Picking a domain itself selects nothing - the domain row is a heading, not a request.
    /// (TreeView.SelectedItem is read-only, so this can't be a binding.)
    /// </summary>
    private void OnDomainTreeSelectionChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is HttpExchangeRowViewModel exchange)
            ViewModel.SelectedExchange = exchange;
    }
}
