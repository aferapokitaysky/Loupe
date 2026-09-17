using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using Loupe.App.Services;

namespace Loupe.App.ViewModels;

/// <summary>
/// One domain in the proxy's sidebar, with the requests made to it underneath - the
/// domain-first way of reading traffic rather than one flat chronological list.
/// </summary>
public sealed partial class DomainGroupViewModel : ObservableObject
{
    private readonly FaviconService _favicons;

    public DomainGroupViewModel(string host, FaviconService favicons)
    {
        Host = host;
        _favicons = favicons;
        RequestFavicon();
    }

    public string Host { get; }

    /// <summary>Newest first: the request you just made is the one you want to look at.</summary>
    public ObservableCollection<HttpExchangeRowViewModel> Exchanges { get; } = [];

    [ObservableProperty] private ImageSource? _favicon;
    [ObservableProperty] private bool _isExpanded = true;

    /// <summary>Ticked in the sidebar to filter the request list. Several at once is the point.</summary>
    [ObservableProperty] private bool _isChecked;

    /// <summary>When the latest request to this domain started, for "most recent" sorting.</summary>
    [ObservableProperty] private DateTimeOffset _lastActivity;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    private int _requestCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    private long _totalBytes;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    [NotifyPropertyChangedFor(nameof(HasErrors))]
    private int _errorCount;

    public bool HasErrors => ErrorCount > 0;

    public string Initial => Host.Length > 0 ? Host[..1].ToUpperInvariant() : "?";

    public string Summary => ErrorCount > 0
        ? $"{RequestCount} · {FormatBytes(TotalBytes)} · {ErrorCount}!"
        : $"{RequestCount} · {FormatBytes(TotalBytes)}";

    public void Add(HttpExchangeRowViewModel row)
    {
        // The request list shows the site's icon too, and it is the domain that knows it.
        row.Favicon = Favicon;
        Exchanges.Insert(0, row);
        LastActivity = row.Exchange.StartTime;
        Recount();
    }

    /// <summary>Totals are recomputed rather than incremented: an exchange is updated in place
    /// as it progresses, so its size and error state are not final when it first arrives.</summary>
    public void Recount()
    {
        RequestCount = Exchanges.Count;

        long bytes = 0;
        int errors = 0;
        foreach (var row in Exchanges)
        {
            bytes += row.ResponseSize;
            if (row.IsError) errors++;
        }

        TotalBytes = bytes;
        ErrorCount = errors;
    }

    /// <summary>The icon usually lands after the first requests have; hand it down when it does.</summary>
    partial void OnFaviconChanged(ImageSource? value)
    {
        foreach (var row in Exchanges) row.Favicon = value;
    }

    /// <summary>async void can only throw into the dispatcher; a missing icon is not worth an error dialog.</summary>
    private async void RequestFavicon()
    {
        try
        {
            Favicon = await _favicons.GetAsync(Host);
        }
        catch (Exception)
        {
            Favicon = null;
        }
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        _ => $"{bytes / (1024.0 * 1024):F1} MB",
    };
}
