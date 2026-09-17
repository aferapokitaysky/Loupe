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

    /// <summary>
    /// Everything you can do with one captured request. Ordered by what people reach for:
    /// send it again, take it somewhere else, keep the answer, then the hiding rules.
    /// </summary>
    private void AddExchangeItems(ContextMenu menu, HttpExchangeRowViewModel exchange)
    {
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_Replay"), "ArrowRepeatAll24",
            () => ViewModel.ReplayCommand.Execute(exchange)));
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_OpenInBrowser"), "Open24",
            () => ViewModel.OpenInBrowserCommand.Execute(exchange)));

        menu.Items.Add(new Separator());
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_CopyUrl"), "Link24", () => CopyAs(exchange, "url")));
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_CopyCurl"), "Code24", () => CopyAs(exchange, "curl")));
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_CopyPowerShell"), "WindowConsole20", () => CopyAs(exchange, "powershell")));
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_CopyFetch"), "BracesVariable24", () => CopyAs(exchange, "fetch")));
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_CopyResponse"), "Copy24", () => CopyAs(exchange, "response")));
        menu.Items.Add(ContextMenus.Item(Loc.Get("Proxy_SaveBody"), "ArrowDownload24",
            () => ViewModel.SaveResponseBodyCommand.Execute(exchange)));

        menu.Items.Add(new Separator());
        menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideHost", exchange.Host), "EyeOff24",
            () => ViewModel.HideDomain(exchange.Host)));

        if (!string.IsNullOrEmpty(exchange.Client))
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideProcess", exchange.Client), "AppsListDetail24",
                () => ViewModel.HideClient(exchange.Client)));
    }

    private void CopyAs(HttpExchangeRowViewModel exchange, string format) =>
        ViewModel.CopyAsCommand.Execute((exchange, format));
}
