using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Loupe.App.Localization;
using Loupe.App.Services;
using Loupe.App.ViewModels;

namespace Loupe.App.Views;

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

    /// <summary>Ctrl+F: put the caret in this page's search box, text selected.</summary>
    public void FocusSearch()
    {
        SearchBox.Focus();
        SearchBox.SelectAll();
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
            () => ViewModel.ShowOnly(host)));
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

        if (row.Packet.Tcp is not null)
        {
            menu.Items.Add(ContextMenus.Item(Loc.Get("Pkt_Follow"), "TextBulletListTree24", () => FollowStream(row)));
            menu.Items.Add(new Separator());
        }

        menu.Items.Add(ContextMenus.Item(Loc.Get("Pkt_CopyRow"), "Copy24",
            () => ClipboardService.TrySetText(
                $"{row.Number}\t{row.Time}\t{row.Source}\t{row.Destination}\t{row.Protocol}\t{row.Length}\t{row.Info}")));
        menu.Items.Add(ContextMenus.Item(Loc.Format("Pkt_CopyAddress", row.SourceAddressText), "ArrowUpload24",
            () => ClipboardService.TrySetText(row.SourceAddressText)));
        menu.Items.Add(ContextMenus.Item(Loc.Format("Pkt_CopyAddress", row.DestinationAddressText), "ArrowDownload24",
            () => ClipboardService.TrySetText(row.DestinationAddressText)));
        menu.Items.Add(ContextMenus.Item(Loc.Get("Pkt_CopyHex"), "Code24",
            () => ClipboardService.TrySetText(row.HexDump)));

        if (row.RemoteHost is { } remote || !string.IsNullOrEmpty(row.Process))
            menu.Items.Add(new Separator());

        if (row.RemoteHost is { } host)
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideHost", host), "EyeOff24", () => ViewModel.HideHost(host)));

        if (!string.IsNullOrEmpty(row.Process))
            menu.Items.Add(ContextMenus.Item(Loc.Format("Ignore_HideProcess", row.Process), "AppsListDetail24",
                () => ViewModel.HideProcess(row.Process)));
    }

    /// <summary>
    /// Opens this packet's whole TCP conversation, reassembled. Non-modal and owned by the main
    /// window, so several streams can be compared side by side while the capture keeps running.
    /// </summary>
    private void FollowStream(PacketRowViewModel row)
    {
        if (ViewModel.FollowStream(row) is not { } stream) return;

        new FollowStreamWindow(stream) { Owner = Window.GetWindow(this) }.Show();
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
