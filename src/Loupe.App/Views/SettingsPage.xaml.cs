using System.Windows.Controls;
using Loupe.App.ViewModels;

namespace Loupe.App.Views;

public partial class SettingsPage : UserControl
{
    public SettingsViewModel ViewModel { get; } = new();

    public SettingsPage()
    {
        InitializeComponent();
        DataContext = ViewModel;
    }
}
