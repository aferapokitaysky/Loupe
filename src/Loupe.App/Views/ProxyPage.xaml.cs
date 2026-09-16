using System.Windows;
using System.Windows.Controls;
using Loupe.App.Localization;
using Loupe.App.ViewModels;

namespace Loupe.App.Views;

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

    /// <summary>Ctrl+F: put the caret in this page's search box, text selected.</summary>
    public void FocusSearch()
    {
        SearchBox.Focus();
        SearchBox.SelectAll();
    }

    /// <summary>Right-click in the sidebar: a domain offers to hide itself, a request its domain and app.</summary>
    private void OnDomainTreeContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var menu = DomainTree.ContextMenu!;
        menu.Items.Clear();

        // The request is checked first: its template sits inside its domain's container, so walking
        // up from a request would otherwise stop at the domain.
        if (ContextMenus.FindDataContext<HttpExchangeRowViewModel>(e.OriginalSource) is { } exchange)
            AddExchangeItems(menu, exchange);
        else if (ContextMenus.FindDataContext<DomainGroupViewModel>(e.OriginalSource) is { } domain)
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideHost", domain.Host), "EyeOff24",
                () => ViewModel.HideDomain(domain.Host)));

        if (menu.Items.Count == 0) e.Handled = true;
    }

    private void OnExchangeGridContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var menu = ExchangeGrid.ContextMenu!;
        menu.Items.Clear();

        if (ContextMenus.FindDataContext<HttpExchangeRowViewModel>(e.OriginalSource) is { } exchange)
            AddExchangeItems(menu, exchange);

        if (menu.Items.Count == 0) e.Handled = true;
    }

    private void AddExchangeItems(ContextMenu menu, HttpExchangeRowViewModel exchange)
    {
        menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideHost", exchange.Host), "EyeOff24",
            () => ViewModel.HideDomain(exchange.Host)));

        if (!string.IsNullOrEmpty(exchange.Client))
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideProcess", exchange.Client), "AppsListDetail24",
                () => ViewModel.HideClient(exchange.Client)));

        menu.Items.Add(new Separator());
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_CopyUrl"), "Copy24", () =>
        {
            // Another program holding the clipboard open makes this throw; that's not worth a crash.
            try { Clipboard.SetText(exchange.Url); }
            catch (System.Runtime.InteropServices.COMException) { }
        }));
    }
}
