using System.Collections.Specialized;
using System.Windows;
using NetSniffer.App.ViewModels;
using Wpf.Ui.Controls;

namespace NetSniffer.App.Views;

public partial class MainWindow : FluentWindow
{
    private readonly MainViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();

        _viewModel = new MainViewModel();
        DataContext = _viewModel;

        _viewModel.Packets.CollectionChanged += OnPacketsCollectionChanged;
        Closed += (_, _) => _viewModel.Dispose();
    }

    private void OnPacketsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (!_viewModel.AutoScroll) return;
        if (e.Action != NotifyCollectionChangedAction.Add || PacketGrid.Items.Count == 0) return;

        PacketGrid.ScrollIntoView(PacketGrid.Items[^1]);
    }
}
