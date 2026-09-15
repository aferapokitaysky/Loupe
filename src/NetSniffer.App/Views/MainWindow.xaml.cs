using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using NetSniffer.App.Localization;
using Wpf.Ui.Controls;

namespace NetSniffer.App.Views;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        Closed += (_, _) =>
        {
            PacketsPage.ViewModel.Dispose();
            ProxyPageControl.ViewModel.Dispose();
        };

        // Set the initial nav selection here, not via IsChecked="True" in XAML: a RadioButton
        // raises Checked synchronously as soon as its IsChecked is set, which during XAML parsing
        // happens before later sibling elements (PacketsPage/ProxyPageControl) are constructed -
        // the handler would run against still-null fields and crash startup.
        PacketsNavButton.IsChecked = true;

        LanguageList.SelectedItem = LocalizationService.CurrentLanguage;
        ShowCurrentFlag();
    }

    private void OnPacketsNavChecked(object sender, RoutedEventArgs e)
    {
        if (PacketsPage is null || ProxyPageControl is null) return;
        CrossFade(showPage: PacketsPage, hidePage: ProxyPageControl);
    }

    private void OnProxyNavChecked(object sender, RoutedEventArgs e)
    {
        if (PacketsPage is null || ProxyPageControl is null) return;
        CrossFade(showPage: ProxyPageControl, hidePage: PacketsPage);
    }

    private static void CrossFade(FrameworkElement showPage, FrameworkElement hidePage)
    {
        if (showPage.Visibility == Visibility.Visible && hidePage.Visibility == Visibility.Collapsed)
            return; // already showing - don't replay the animation, e.g. on startup

        var easeOut = new CubicEase { EasingMode = EasingMode.EaseOut };

        showPage.Visibility = Visibility.Visible;
        showPage.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)) { EasingFunction = easeOut });

        var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(130));
        fadeOut.Completed += (_, _) => hidePage.Visibility = Visibility.Collapsed;
        hidePage.BeginAnimation(OpacityProperty, fadeOut);
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
