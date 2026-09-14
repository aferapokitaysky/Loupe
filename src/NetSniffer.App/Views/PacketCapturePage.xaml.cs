using System.Collections.Specialized;
using System.Windows.Controls;
using NetSniffer.App.ViewModels;

namespace NetSniffer.App.Views;

public partial class PacketCapturePage : UserControl
{
    public MainViewModel ViewModel { get; } = new();

    public PacketCapturePage()
    {
        InitializeComponent();
        DataContext = ViewModel;
        ViewModel.Packets.CollectionChanged += OnPacketsCollectionChanged;
    }

    private void OnPacketsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (!ViewModel.AutoScroll) return;
        if (e.Action != NotifyCollectionChangedAction.Add || PacketGrid.Items.Count == 0) return;

        PacketGrid.ScrollIntoView(PacketGrid.Items[^1]);
    }
}
