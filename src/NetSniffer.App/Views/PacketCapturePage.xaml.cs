using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
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
