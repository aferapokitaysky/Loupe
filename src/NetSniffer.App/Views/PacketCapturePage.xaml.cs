using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using NetSniffer.App.Localization;
using NetSniffer.App.ViewModels;

namespace NetSniffer.App.Views;

public partial class PacketCapturePage : UserControl
{
    private ScrollViewer? _gridScroller;
    private bool _scrollQueued;

    public MainViewModel ViewModel { get; } = new();

    public PacketCapturePage()
    {
        InitializeComponent();
        DataContext = ViewModel;

        // Deliberately NOT Packets.CollectionChanged: scrolling from inside a collection
        // notification runs while the DataGrid's own generator is still catching up with the
        // very same event, and the grid then throws
        //   "ItemsControl is inconsistent with its items source ... accumulated count 115
        //    differs from actual count 116".
        // PacketsAppended fires once per drain tick, after the batch is in.
        ViewModel.PacketsAppended += OnPacketsAppended;
    }

    private void OnPacketsAppended(object? sender, EventArgs e)
    {
        if (!ViewModel.AutoScroll || _scrollQueued) return;

        // Background priority: let the generator, measure and arrange passes finish first,
        // and coalesce bursts into a single scroll instead of one per batch.
        _scrollQueued = true;
        Dispatcher.BeginInvoke(DispatcherPriority.Background, ScrollToNewest);
    }

    private void ScrollToNewest()
    {
        _scrollQueued = false;
        if (!ViewModel.AutoScroll) return;

        // ScrollToEnd on the template's own ScrollViewer, not DataGrid.ScrollIntoView: it
        // costs one scroll offset change instead of forcing the virtualizing panel to
        // realize a container for the last row on every batch.
        _gridScroller ??= FindScrollViewer(PacketGrid);
        _gridScroller?.ScrollToEnd();
    }

    // ---------------------------------------------------------------- context menus

    /// <summary>Right-click on a host: hide it, hide its programs, or show only its traffic.</summary>
    private void OnHostListContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (ContextMenus.FindDataContext<HostRowViewModel>(e.OriginalSource) is not { } host)
        {
            e.Handled = true; // blank space under the list: nothing to offer
            return;
        }

        var menu = HostList.ContextMenu!;
        menu.Items.Clear();

        menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_OnlyThisHost", host.Name), "Filter24",
            () => ViewModel.SelectedHost = host));
        menu.Items.Add(new Separator());
        menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideHost", host.Name), "EyeOff24",
            () => ViewModel.HideHost(host.HasName ? host.Name : host.Address)));

        foreach (var process in host.ProcessNames)
        {
            string name = process;
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideProcess", name), "AppsListDetail24",
                () => ViewModel.HideProcess(name)));
        }
    }

    /// <summary>Right-click on a packet: hide its program or its remote host.</summary>
    private void OnPacketGridContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (ContextMenus.FindDataContext<PacketRowViewModel>(e.OriginalSource) is not { } row)
        {
            e.Handled = true; // header or empty area
            return;
        }

        var menu = PacketGrid.ContextMenu!;
        menu.Items.Clear();

        if (row.RemoteHost is { } remote)
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideHost", remote), "EyeOff24", () => ViewModel.HideHost(remote)));

        if (!string.IsNullOrEmpty(row.Process))
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideProcess", row.Process), "AppsListDetail24",
                () => ViewModel.HideProcess(row.Process)));

        if (menu.Items.Count == 0) e.Handled = true; // e.g. an ARP frame: no host, no program
    }

    private static ScrollViewer? FindScrollViewer(DependencyObject root)
    {
        if (root is ScrollViewer found) return found;

        int count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            if (FindScrollViewer(VisualTreeHelper.GetChild(root, i)) is { } scroller)
                return scroller;
        }

        return null;
    }
}
