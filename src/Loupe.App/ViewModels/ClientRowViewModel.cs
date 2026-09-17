using CommunityToolkit.Mvvm.ComponentModel;
using Loupe.App.Services;

namespace Loupe.App.ViewModels;

/// <summary>
/// One program whose requests came through the proxy: its name, its icon, how much it asked
/// for. The other half of "who is talking to whom" - the domain list answers the "to whom".
/// </summary>
public sealed partial class ClientRowViewModel : ObservableObject
{
    public ClientRowViewModel(string name, string? imagePath)
    {
        Name = name;
        ImagePath = imagePath;
        IsBrowser = LooksLikeBrowser(name);
    }

    public string Name { get; }
    public string? ImagePath { get; }

    /// <summary>Loaded on first display, on the UI thread (see <see cref="AppIconService"/>).</summary>
    public System.Windows.Media.ImageSource? Icon => AppIconService.Get(ImagePath);

    /// <summary>Ticked to narrow the request list to this program. Several at once is the point.</summary>
    [ObservableProperty] private bool _isChecked;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    private int _requestCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    private long _totalBytes;

    [ObservableProperty] private DateTimeOffset _lastActivity;

    public string Summary => $"{RequestCount} · {FormatBytes(TotalBytes)}";

    public string Initial => Name.Length > 0 ? Name[..1].ToUpperInvariant() : "?";

    /// <summary>
    /// Whether this looks like a web browser, which is what "web only" filters on.
    ///
    /// A name list rather than anything clever: Windows has no flag that says "this is a
    /// browser", and the alternative - guessing from behaviour - would quietly miss the browser
    /// you actually use. Anything missing can still be ticked by hand, and the list is easy to
    /// add to.
    /// </summary>
    public bool IsBrowser { get; }

    private static readonly HashSet<string> BrowserNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "edge", "firefox", "librewolf", "waterfox", "floorp", "zen",
        "opera", "opera_gx", "launcher", "brave", "vivaldi", "chromium", "thorium",
        "browser", "yandex", "duckduckgo", "arc", "tor", "iexplore", "safari", "midori",
        "webview2", "msedgewebview2", "ucbrowser", "maxthon", "palemoon", "seamonkey",
    };

    public static bool LooksLikeBrowser(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;

        string trimmed = name.Trim();
        if (BrowserNames.Contains(trimmed)) return true;

        // "DuckDuckGo.WebView", "Chrome Beta", "Firefox Developer Edition": the family name is
        // in there, and a browser under a slightly different name is still a browser.
        return BrowserNames.Any(known =>
            known.Length >= 4 && trimmed.Contains(known, StringComparison.OrdinalIgnoreCase));
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        _ => $"{bytes / (1024.0 * 1024):F1} MB",
    };
}
