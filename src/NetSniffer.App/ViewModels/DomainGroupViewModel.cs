using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using NetSniffer.App.Services;

namespace NetSniffer.App.ViewModels;

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
        Exchanges.Insert(0, row);
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

    private async void RequestFavicon() => Favicon = await _favicons.GetAsync(Host);

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        _ => $"{bytes / (1024.0 * 1024):F1} MB",
    };
}
