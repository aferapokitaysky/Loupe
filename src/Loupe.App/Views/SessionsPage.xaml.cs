using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Loupe.App.Localization;
using Loupe.App.ViewModels;

namespace Loupe.App.Views;

public partial class SessionsPage : UserControl
{
    public SessionsViewModel ViewModel { get; } = new();

    public SessionsPage()
    {
        InitializeComponent();
        DataContext = ViewModel;
    }

    /// <summary>
    /// Deleting a session removes files for good, so it asks first - and the prompt names the
    /// session, because the buttons for several of them sit a few pixels apart.
    /// </summary>
    private void OnDeleteClick(object sender, RoutedEventArgs e)
    {
        // DataContext, not Tag: inside the item template the button's DataContext is the row,
        // while Tag turned out not to survive on a themed control - and a delete button that
        // silently does nothing is worse than one that deletes.
        if (sender is not FrameworkElement { DataContext: SessionRowViewModel row }) return;

        var answer = MessageBox.Show(
            Loc.Format("Sessions_DeleteConfirm", row.Name),
            Loc.Get("Sessions_Delete"),
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (answer == MessageBoxResult.Yes) ViewModel.Delete(row);
    }

    private void OnRenameKeyDown(object sender, KeyEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: SessionRowViewModel row }) return;

        switch (e.Key)
        {
            case Key.Enter:
                ViewModel.CommitRenameCommand.Execute(row);
                e.Handled = true;
                break;

            case Key.Escape:
                ViewModel.CancelRenameCommand.Execute(row);
                e.Handled = true;
                break;
        }
    }

    /// <summary>
    /// Clicking away keeps what was typed, the way renaming a file in Explorer does - leaving the
    /// box open with an unsaved name was the surprising outcome.
    /// </summary>
    private void OnRenameLostFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: SessionRowViewModel { IsRenaming: true } row })
            ViewModel.CommitRenameCommand.Execute(row);
    }

    /// <summary>Focus lands in the box the moment it appears, with the old name selected.</summary>
    private void OnRenameBoxLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is not Wpf.Ui.Controls.TextBox box || box.Visibility != Visibility.Visible) return;

        box.Focus();
        box.SelectAll();
    }
}
