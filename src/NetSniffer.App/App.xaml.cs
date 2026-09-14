using System.Collections.Generic;
using System.Windows;
using NetSniffer.App.Localization;

namespace NetSniffer.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Must run before StartupUri creates MainWindow, so every DynamicResource
        // in the visual tree resolves against the right language on first render.
        LocalizationService.Initialize();

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(
                $"Unexpected error:\n\n{DescribeWithInnerExceptions(args.Exception)}",
                "NetSniffer",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };
    }

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
