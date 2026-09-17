using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Input;
using System.Windows.Media.Animation;
using Loupe.App.Localization;
using Wpf.Ui.Controls;

namespace Loupe.App.Views;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        RestorePlacement();
        Closed += (_, _) =>
        {
            SavePlacement();
            PacketsPage.ViewModel.Dispose();
            ProxyPageControl.ViewModel.Dispose();
        };

        // Set the initial nav selection here, not via IsChecked="True" in XAML: a RadioButton
        // raises Checked synchronously as soon as its IsChecked is set, which during XAML parsing
        // happens before later sibling elements (PacketsPage/ProxyPageControl) are constructed -
        // the handler would run against still-null fields and crash startup.
        PacketsNavButton.IsChecked = true;

        // Saving on either page adds to the library; opening a session routes it to the page
        // that can show it, so the list and the pages stay in step without either polling.
        PacketsPage.ViewModel.SessionSaved += (_, _) => SessionsPageControl.ViewModel.Refresh();
        ProxyPageControl.ViewModel.SessionSaved += (_, _) => SessionsPageControl.ViewModel.Refresh();
        SessionsPageControl.ViewModel.OpenRequested += OnSessionOpenRequested;

        LanguageList.SelectedItem = LocalizationService.CurrentLanguage;
        ShowCurrentFlag();

        // Loaded, not here: reading starts a background task that reports through the view
        // model, and there is nothing to report into until the window is actually up.
        if (App.StartupCapturePath is { } capture)
            Loaded += (_, _) => PacketsPage.ViewModel.LoadCaptureFile(capture);
    }


    /// <summary>
    /// Puts the window back where it was left. Checked against the current screens first: a
    /// position saved on a monitor that is no longer attached would open the window off-screen,
    /// where it cannot be dragged back.
    /// </summary>
    private void RestorePlacement()
    {
        var saved = Services.AppSettings.Current;
        if (double.IsNaN(saved.WindowWidth) || double.IsNaN(saved.WindowHeight)) return;

        double virtualLeft = SystemParameters.VirtualScreenLeft;
        double virtualTop = SystemParameters.VirtualScreenTop;
        double virtualRight = virtualLeft + SystemParameters.VirtualScreenWidth;
        double virtualBottom = virtualTop + SystemParameters.VirtualScreenHeight;

        Width = Math.Clamp(saved.WindowWidth, MinWidth, SystemParameters.VirtualScreenWidth);
        Height = Math.Clamp(saved.WindowHeight, MinHeight, SystemParameters.VirtualScreenHeight);

        // At least a title bar's worth has to stay on a screen for the window to be usable.
        bool onScreen = !double.IsNaN(saved.WindowLeft) && !double.IsNaN(saved.WindowTop)
                        && saved.WindowLeft + 120 < virtualRight && saved.WindowLeft + Width - 120 > virtualLeft
                        && saved.WindowTop + 60 < virtualBottom && saved.WindowTop >= virtualTop - 8;

        if (onScreen)
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = saved.WindowLeft;
            Top = saved.WindowTop;
        }

        if (saved.WindowMaximized) WindowState = WindowState.Maximized;
    }

    private void SavePlacement() => Services.AppSettings.Update(settings =>
    {
        // RestoreBounds, not Left/Width: while maximized those describe the maximized frame,
        // and restoring from them would leave the window unable to become small again.
        var bounds = WindowState == WindowState.Normal
            ? new Rect(Left, Top, Width, Height)
            : RestoreBounds;

        settings.WindowLeft = bounds.Left;
        settings.WindowTop = bounds.Top;
        settings.WindowWidth = bounds.Width;
        settings.WindowHeight = bounds.Height;
        settings.WindowMaximized = WindowState == WindowState.Maximized;
    });

    /// <summary>
    /// Shortcuts that act on whichever page is in front, so the same key does the obvious thing
    /// everywhere: save what I am looking at, search it, clear it.
    /// </summary>
    private void OnWindowKeyDown(object sender, KeyEventArgs e)
    {
        bool control = (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control;

        switch (e.Key)
        {
            case Key.S when control:
                if (PacketsPage.Visibility == Visibility.Visible) PacketsPage.ViewModel.SaveSessionCommand.Execute(null);
                else if (ProxyPageControl.Visibility == Visibility.Visible) ProxyPageControl.ViewModel.SaveSessionCommand.Execute(null);
                e.Handled = true;
                break;

            case Key.F when control:
                if (PacketsPage.Visibility == Visibility.Visible) PacketsPage.FocusSearch();
                else if (ProxyPageControl.Visibility == Visibility.Visible) ProxyPageControl.FocusSearch();
                e.Handled = true;
                break;

            case Key.L when control:
                if (PacketsPage.Visibility == Visibility.Visible) PacketsPage.ViewModel.ClearPacketsCommand.Execute(null);
                else if (ProxyPageControl.Visibility == Visibility.Visible) ProxyPageControl.ViewModel.ClearExchangesCommand.Execute(null);
                e.Handled = true;
                break;

            // Repeat the selected request, the shortcut you want while watching one endpoint fail.
            case Key.R when control:
                if (ProxyPageControl.Visibility == Visibility.Visible)
                    ProxyPageControl.ViewModel.ReplayCommand.Execute(ProxyPageControl.ViewModel.SelectedExchange);
                e.Handled = true;
                break;

            case Key.F5:
                if (SessionsPageControl.Visibility == Visibility.Visible) SessionsPageControl.ViewModel.Refresh();
                e.Handled = true;
                break;

            case Key.F1:
                SettingsNavButton.IsChecked = true;
                e.Handled = true;
                break;
        }
    }

    /// <summary>Opens a saved session on the page it belongs to, and goes there.</summary>
    private void OnSessionOpenRequested(object? sender, Loupe.Core.Sessions.SessionInfo session)
    {
        string capture = System.IO.Path.Combine(session.Directory, Loupe.Core.Sessions.SessionStore.CaptureFileName);
        string requests = System.IO.Path.Combine(session.Directory, Loupe.Core.Sessions.SessionStore.RequestsFileName);

        // A session can hold both; the packets are the bigger half, so they win the navigation.
        if (System.IO.File.Exists(capture))
        {
            PacketsPage.ViewModel.LoadCaptureFile(capture);
            if (System.IO.File.Exists(requests)) ProxyPageControl.ViewModel.LoadSession(session);
            PacketsNavButton.IsChecked = true;
        }
        else if (System.IO.File.Exists(requests))
        {
            ProxyPageControl.ViewModel.LoadSession(session);
            ProxyNavButton.IsChecked = true;
        }
    }

    private void OnPacketsNavChecked(object sender, RoutedEventArgs e) => ShowPage(PacketsPage);

    private void OnProxyNavChecked(object sender, RoutedEventArgs e) => ShowPage(ProxyPageControl);

    private void OnSettingsNavChecked(object sender, RoutedEventArgs e)
    {
        // What is on disk can change while the app runs (sessions saved, icons cached), so the
        // page recounts on the way in rather than showing a figure from startup.
        SettingsPageControl?.ViewModel.RefreshUsageCommand.Execute(null);
        ShowPage(SettingsPageControl);
    }

    private void OnSessionsNavChecked(object sender, RoutedEventArgs e)
    {
        // Sessions are files on disk that the other pages write; re-read them on the way in
        // rather than showing whatever the list held when the window opened.
        SessionsPageControl?.ViewModel.Refresh();
        ShowPage(SessionsPageControl);
    }

    /// <summary>Cross-fades to one page and puts every other one away.</summary>
    private void ShowPage(FrameworkElement? target)
    {
        // Checked fires while XAML is still being parsed, before the later siblings exist.
        if (PacketsPage is null || ProxyPageControl is null || SessionsPageControl is null
            || SettingsPageControl is null || target is null) return;

        if (target.Visibility == Visibility.Visible && target.Opacity > 0.99)
            return; // already showing - don't replay the animation, e.g. on startup

        var easeOut = new CubicEase { EasingMode = EasingMode.EaseOut };

        target.Visibility = Visibility.Visible;
        target.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)) { EasingFunction = easeOut });

        foreach (var page in new FrameworkElement[] { PacketsPage, ProxyPageControl, SessionsPageControl, SettingsPageControl })
        {
            if (ReferenceEquals(page, target) || page.Visibility != Visibility.Visible) continue;

            var hiding = page;
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(130));
            fadeOut.Completed += (_, _) => hiding.Visibility = Visibility.Collapsed;
            hiding.BeginAnimation(OpacityProperty, fadeOut);
        }
    }

    private void OnLanguageSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LanguageList.SelectedItem is not LanguageInfo language) return;

        if (language.Code != LocalizationService.CurrentLanguage.Code)
            LocalizationService.SetLanguage(language.Code);

        ShowCurrentFlag();
        LanguageToggle.IsChecked = false;
    }

    // StaysOpen="False" dismisses the popup on an outside click but leaves the toggle
    // checked, which would swallow the next click on it - clear it when the popup closes.
    private void OnLanguagePopupClosed(object? sender, EventArgs e) => LanguageToggle.IsChecked = false;

    private void ShowCurrentFlag() =>
        CurrentFlag.Background = TryFindResource(LocalizationService.CurrentLanguage.FlagKey) as Brush ?? Brushes.Transparent;
}
