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
    /// Picking a domain narrows the request list to it; picking a request opens it and keeps the
    /// list on that request's domain, so the grid and the tree never disagree about what you are
    /// looking at. (TreeView.SelectedItem is read-only, so this can't be a binding.)
    /// </summary>
    private void OnDomainTreeSelectionChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        switch (e.NewValue)
        {
            case DomainGroupViewModel domain:
                ViewModel.SelectedDomain = domain;
                break;

            case HttpExchangeRowViewModel exchange:
                ViewModel.SelectedDomain = ViewModel.Domains.FirstOrDefault(d =>
                    string.Equals(d.Host, exchange.Host, StringComparison.OrdinalIgnoreCase));
                ViewModel.SelectedExchange = exchange;
                break;
        }
    }
}
