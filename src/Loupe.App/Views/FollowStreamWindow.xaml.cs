using Loupe.App.ViewModels;

namespace Loupe.App.Views;

/// <summary>Both directions of one TCP conversation, reassembled. Opened from a packet's context menu.</summary>
public partial class FollowStreamWindow : Wpf.Ui.Controls.FluentWindow
{
    public FollowStreamWindow(FollowStreamViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        Title = viewModel.Title;
    }
}
