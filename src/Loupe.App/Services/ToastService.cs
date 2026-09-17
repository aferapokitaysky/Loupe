using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;

namespace Loupe.App.Services;

/// <summary>
/// Short-lived confirmations in the corner of the window: copied, repeated, saved.
///
/// They exist because the action and the answer were in different places - you copy a request
/// at the pointer and the status line reports it at the bottom of the window, which nobody
/// looks at. A toast says it where you are looking, then gets out of the way.
/// </summary>
public static class ToastService
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(3.2);

    /// <summary>At most this many at once; older ones are pushed out rather than stacking down the screen.</summary>
    private const int MaxVisible = 3;

    public static ObservableCollection<Toast> Items { get; } = [];

    public static void Show(string message, string symbol = "Checkmark24")
    {
        if (string.IsNullOrWhiteSpace(message)) return;

        // Callers include background continuations (a replay finishing, a fetch failing), and
        // the collection is bound to the UI.
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null) return;

        if (!dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => Show(message, symbol));
            return;
        }

        var toast = new Toast(message, symbol);
        Items.Add(toast);
        while (Items.Count > MaxVisible) Items.RemoveAt(0);

        var timer = new DispatcherTimer { Interval = Lifetime };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            Items.Remove(toast);
        };
        timer.Start();
    }
}

public sealed record Toast(string Message, string Symbol);
