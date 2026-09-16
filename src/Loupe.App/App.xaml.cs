using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;
using Loupe.App.Localization;
using Wpf.Ui.Appearance;

namespace Loupe.App;

public partial class App : Application
{
    /// <summary>
    /// The app is deliberately monochrome, so the accent is a near-white rather
    /// than the user's Windows accent colour (which WPF-UI picks up by default and
    /// which turned every primary button and checkbox magenta on this machine).
    /// </summary>
    private static readonly Color MonochromeAccent = Color.FromRgb(0xDD, 0xE3, 0xE9);

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        ApplicationAccentColorManager.Apply(MonochromeAccent, ApplicationTheme.Dark);
        ApplyPrimaryButtonPalette();

        // Must run before StartupUri creates MainWindow, so every DynamicResource
        // in the visual tree resolves against the right language on first render.
        LocalizationService.Initialize();

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(
                $"Unexpected error:\n\n{DescribeWithInnerExceptions(args.Exception)}",
                "Loupe",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };
    }

    /// <summary>
    /// Primary ("Appearance=Primary") buttons: a near-white fill with near-black text,
    /// so the main action still stands out in a monochrome UI. Has to run after
    /// ApplicationAccentColorManager.Apply, which writes these same keys into
    /// Application.Resources and would otherwise overwrite them.
    /// </summary>
    private void ApplyPrimaryButtonPalette()
    {
        SetBrush("AccentButtonBackground", 0xE6, 0xEA, 0xEE);
        SetBrush("AccentButtonBackgroundPointerOver", 0xF3, 0xF6, 0xF8);
        SetBrush("AccentButtonBackgroundPressed", 0xC6, 0xCD, 0xD4);
        SetBrush("AccentButtonForeground", 0x0A, 0x0B, 0x0D);
        SetBrush("AccentButtonForegroundPointerOver", 0x0A, 0x0B, 0x0D);
        SetBrush("AccentButtonForegroundPressed", 0x14, 0x18, 0x1C);
        SetBrush("AccentButtonBorderBrushPressed", 0x9A, 0xA2, 0xAA);
    }

    private void SetBrush(string resourceKey, byte r, byte g, byte b) =>
        Resources[resourceKey] = new SolidColorBrush(Color.FromRgb(r, g, b));

    // TargetInvocationException and similar wrapper exceptions hide the actually
    // useful message in InnerException - unwrap the whole chain for the dialog.
    private static string DescribeWithInnerExceptions(Exception exception)
    {
        var messages = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
            messages.Add($"{current.GetType().Name}: {current.Message}");
        return string.Join("\n\n→ ", messages);
    }
}
