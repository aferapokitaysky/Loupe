using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Loupe.App.Localization;
using Loupe.App.Services;
using Loupe.Capture.Processes;
using Loupe.Core;
using Loupe.Core.Sessions;
using Loupe.Proxy;
using Loupe.Proxy.Ca;
using Loupe.Proxy.Http;

namespace Loupe.App.ViewModels;

public partial class ProxyViewModel : ObservableObject, IDisposable
{
    private const int MaxExchanges = 50_000;
    private const int DrainBatchSize = 500;

    private readonly ConcurrentQueue<HttpExchange> _incoming = new();
    private readonly Dictionary<long, HttpExchangeRowViewModel> _rowsById = [];
    private readonly DispatcherTimer _drainTimer;
    // Explicit path rather than the proxy computing its own: the CA must land under the same
    // storage root the rest of the app migrates, whatever order things happen to start in.
    private readonly RootCertificateAuthority _ca = new(AppStorage.PathTo("ca"));

    private ProxyServer? _server;

    /// <summary>
    /// Whether *this app* turned the Windows system proxy on. Pointing Windows at a proxy
    /// that is no longer listening takes the machine offline, so anything that stops the
    /// proxy - including closing the app - has to undo our own change.
    /// </summary>
    private bool _weEnabledSystemProxy;

    public ObservableCollection<HttpExchangeRowViewModel> Exchanges { get; } = [];

    /// <summary>
    /// The same exchanges grouped by host, which is how you actually read a capture: pick the
    /// domain you care about, then the request. A flat chronological list of everything the
    /// machine did is unusable the moment more than one app is talking.
    /// </summary>
    public ObservableCollection<DomainGroupViewModel> Domains { get; } = [];

    private readonly Dictionary<string, DomainGroupViewModel> _domainsByHost = [];

    /// <summary>
    /// The programs whose requests came through, newest activity first. The sidebar can group
    /// by domain or by program, because "what is this app talking to" and "who is talking to
    /// this domain" are both questions people arrive with.
    /// </summary>
    public ObservableCollection<ClientRowViewModel> Clients { get; } = [];

    private readonly Dictionary<string, ClientRowViewModel> _clientsByName = new(StringComparer.OrdinalIgnoreCase);

    private readonly HashSet<string> _clientFilter = new(StringComparer.OrdinalIgnoreCase);
    private readonly FaviconService _favicons = new();

    /// <summary>
    /// The listening port, as text. Bound as a string on purpose: an int binding silently
    /// refuses an empty or half-typed box, leaving a red field, a stale value underneath and a
    /// Start button that looks like it should work. Here the text is always accepted and
    /// validated once, where the result can actually be explained.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsPortValid))]
    [NotifyCanExecuteChangedFor(nameof(StartProxyCommand))]
    private string _portText = AppSettings.Current.ProxyPort.ToString();

    /// <summary>The parsed port, or 0 when the box doesn't hold a usable one.</summary>
    public int Port => int.TryParse(PortText, out int port) && port is > 0 and <= 65535 ? port : 0;

    public bool IsPortValid => Port != 0;

    /// <summary>
    /// Second listener that takes raw connections with no CONNECT line, routing by TLS SNI or
    /// Host header. This is the answer to "it only captures my browser": programs that ignore
    /// the Windows proxy setting can be pointed here instead and are intercepted the same way.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TransparentPort))]
    [NotifyCanExecuteChangedFor(nameof(StartProxyCommand))]
    private string _transparentPortText = AppSettings.Current.TransparentPort.ToString();

    public int TransparentPort =>
        int.TryParse(TransparentPortText, out int port) && port is > 0 and <= 65535 ? port : 0;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartProxyCommand))]
    private bool _transparentEnabled = AppSettings.Current.TransparentProxy;
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleSystemProxyCommand))]
    private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private HttpExchangeRowViewModel? _selectedExchange;
    /// <summary>Domain highlighted in the sidebar. The tick boxes do the filtering, so more than
    /// one domain can be compared at a time.</summary>
    [ObservableProperty] private DomainGroupViewModel? _selectedDomain;

    private readonly HashSet<string> _domainFilter = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The chip's text: one domain by name, or how many are ticked.</summary>
    public string FilterScope
    {
        get
        {
            if (_clientFilter.Count == 1) return _clientFilter.First();
            if (_clientFilter.Count > 1) return Loc.Format("Filter_HostCount", _clientFilter.Count);
            if (BrowserOnly && _domainFilter.Count == 0) return Loc.Get("Proxy_BrowserOnly");

            return _domainFilter.Count switch
            {
                0 => "",
                1 => _domainFilter.First(),
                var many => Loc.Format("Filter_HostCount", many),
            };
        }
    }

    /// <summary>Called when a domain is ticked or unticked.</summary>
    private void OnDomainCheckedChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(DomainGroupViewModel.IsChecked) || sender is not DomainGroupViewModel domain) return;

        if (domain.IsChecked) _domainFilter.Add(domain.Host);
        else _domainFilter.Remove(domain.Host);

        ApplyFilter();
        OnPropertyChanged(nameof(IsFiltered));
        OnPropertyChanged(nameof(FilterScope));
    }

    /// <summary>Ticks one domain and unticks the rest.</summary>
    public void ShowOnly(DomainGroupViewModel domain)
    {
        foreach (var row in Domains)
            row.IsChecked = ReferenceEquals(row, domain);
    }

    // ---- sorting

    public IReadOnlyList<SortOption> DomainSortOptions { get; } =
    [
        new("Recent", "Sort_Recent"),
        new("Requests", "Sort_Requests"),
        new("Bytes", "Sort_Bytes"),
        new("Name", "Sort_Name"),
    ];

    [ObservableProperty] private SortOption _domainSort = new("Recent", "Sort_Recent");

    partial void OnDomainSortChanged(SortOption value) => ApplyDomainSort();

    private void ApplyDomainSort()
    {
        if (System.Windows.Data.CollectionViewSource.GetDefaultView(Domains) is not System.Windows.Data.ListCollectionView view)
            return;

        view.CustomSort = DomainSort.Key switch
        {
            "Requests" => Comparer<object>.Create((a, b) => Compare(b, a, d => d.RequestCount)),
            "Bytes" => Comparer<object>.Create((a, b) => Compare(b, a, d => d.TotalBytes)),
            "Name" => Comparer<object>.Create((a, b) =>
                string.Compare(((DomainGroupViewModel)a).Host, ((DomainGroupViewModel)b).Host, StringComparison.OrdinalIgnoreCase)),
            _ => Comparer<object>.Create((a, b) => Compare(b, a, d => d.LastActivity)),
        };

        view.IsLiveSorting = true;
        foreach (string property in new[] { nameof(DomainGroupViewModel.RequestCount), nameof(DomainGroupViewModel.TotalBytes), nameof(DomainGroupViewModel.LastActivity), nameof(DomainGroupViewModel.Host) })
        {
            if (!view.LiveSortingProperties.Contains(property)) view.LiveSortingProperties.Add(property);
        }

        static int Compare<TKey>(object a, object b, Func<DomainGroupViewModel, TKey> key) where TKey : IComparable<TKey> =>
            key((DomainGroupViewModel)a).CompareTo(key((DomainGroupViewModel)b));
    }

    /// <summary>Search over URL, method, status and the sending app.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private string _searchText = "";

    /// <summary>
    /// Extends the search into request and response bodies. Off by default because it is the
    /// expensive one - "which request carried this id" is worth the wait, typing a host name is not.
    /// </summary>
    [ObservableProperty] private bool _searchBodies;

    /// <summary>
    /// Wrap long lines in the request and response panes. On by default: a body is text to be
    /// read, and a line that runs off to the right is a line nobody reads.
    /// </summary>
    [ObservableProperty] private bool _wrapText = true;

    /// <summary>Narrows the list to failures: 4xx, 5xx and connections that never answered.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private bool _errorsOnly;

    [ObservableProperty] private string _filterSummary = "";

    public bool IsFiltered => _domainFilter.Count > 0 || _clientFilter.Count > 0
                              || !string.IsNullOrWhiteSpace(SearchText) || ErrorsOnly || BrowserOnly;

    partial void OnSearchTextChanged(string value) => ApplyFilter(); // request lists stay small enough

    partial void OnSearchBodiesChanged(bool value) => ApplyFilter();

    partial void OnErrorsOnlyChanged(bool value) => ApplyFilter();

    [RelayCommand]
    private void ClearFilter()
    {
        foreach (var domain in Domains.Where(d => d.IsChecked).ToList())
            domain.IsChecked = false;

        // Unticking rows only reaches domains still in the list. A domain that was ticked and has
        // since been cleared or evicted lives on in the set - and would keep the grid filtered to
        // something nobody can see or untick - so the set is emptied outright.
        foreach (var client in Clients.Where(c => c.IsChecked).ToList())
            client.IsChecked = false;

        ResetDomainFilter();
        ResetClientFilter();
        SearchText = "";
        ErrorsOnly = false;
        BrowserOnly = false;
        ApplyFilter();
    }

    private void ResetDomainFilter()
    {
        if (_domainFilter.Count == 0) return;

        _domainFilter.Clear();
        OnPropertyChanged(nameof(IsFiltered));
        OnPropertyChanged(nameof(FilterScope));
    }

    // ---------------------------------------------------------------- hiding & domain search

    /// <summary>
    /// Which way the sidebar groups what came through: by domain, or by the program that asked.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsGroupedByClient))]
    private bool _groupByClient;

    public bool IsGroupedByClient => GroupByClient;

    /// <summary>
    /// Show only what a browser asked for.
    ///
    /// With Windows pointed at the proxy, everything on the machine arrives: chat apps polling,
    /// updaters, Windows' own connectivity checks. That is the honest picture and sometimes the
    /// interesting one, but "what is this page doing" is the common question, and this is the
    /// answer to it.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private bool _browserOnly;

    partial void OnBrowserOnlyChanged(bool value)
    {
        ApplyFilter();
        ApplyClientFilter();
        UpdateFilterSummary();
    }

    /// <summary>Called when a program is ticked or unticked in the sidebar.</summary>
    private void OnClientCheckedChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(ClientRowViewModel.IsChecked) || sender is not ClientRowViewModel client) return;

        if (client.IsChecked) _clientFilter.Add(client.Name);
        else _clientFilter.Remove(client.Name);

        ApplyFilter();
        OnPropertyChanged(nameof(IsFiltered));
        OnPropertyChanged(nameof(FilterScope));
    }

    /// <summary>Ticks one program and unticks the rest.</summary>
    public void ShowOnlyClient(ClientRowViewModel client)
    {
        foreach (var row in Clients)
            row.IsChecked = ReferenceEquals(row, client);
    }

    private void ResetClientFilter()
    {
        if (_clientFilter.Count == 0) return;

        _clientFilter.Clear();
        OnPropertyChanged(nameof(IsFiltered));
        OnPropertyChanged(nameof(FilterScope));
    }

    private void ApplyClientFilter()
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Clients);
        string search = DomainSearchText.Trim();

        view.Filter = search.Length == 0 && !BrowserOnly
            ? null
            : item => item is ClientRowViewModel client
                      && (!BrowserOnly || client.IsBrowser)
                      && (search.Length == 0 || client.Name.Contains(search, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Search over the domain sidebar: host name, or an app that talked to it.</summary>
    [ObservableProperty] private string _domainSearchText = "";

    partial void OnDomainSearchTextChanged(string value)
    {
        ApplyDomainFilter();
        ApplyClientFilter();
    }

    public bool HasHidden => !IgnoreListStore.Rules.IsEmpty;
    public string HiddenSummary => Loc.Format("Ignore_Summary", IgnoreListStore.Rules.Describe());

    private HashSet<string> _hiddenDomains = new(StringComparer.OrdinalIgnoreCase);

    public void HideDomain(string? host) => IgnoreListStore.Rules.AddHost(host);
    public void HideClient(string? client) => IgnoreListStore.Rules.AddProcess(client);

    [RelayCommand]
    private void ShowHidden() => IgnoreListStore.Rules.Clear();

    private void OnIgnoreRulesChanged(object? sender, EventArgs e)
    {
        if (SelectedDomain is { } selected && IsDomainHidden(selected)) SelectedDomain = null;

        ApplyFilter();
        ApplyDomainFilter();
        OnPropertyChanged(nameof(HasHidden));
        OnPropertyChanged(nameof(HiddenSummary));
    }

    private static bool IsExchangeHidden(HttpExchangeRowViewModel row)
    {
        var rules = IgnoreListStore.Rules;
        return !rules.IsEmpty && (rules.IsHostIgnored(row.Host) || rules.IsProcessIgnored(row.Exchange.Client?.Name));
    }

    /// <summary>Hidden by name, or because every request to it came from a hidden app.</summary>
    private static bool IsDomainHidden(DomainGroupViewModel domain)
    {
        var rules = IgnoreListStore.Rules;
        if (rules.IsEmpty) return false;
        if (rules.IsHostIgnored(domain.Host)) return true;
        return domain.Exchanges.Count > 0 && domain.Exchanges.All(IsExchangeHidden);
    }

    private void ApplyDomainFilter()
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Domains);
        string search = DomainSearchText.Trim();
        bool hiding = !IgnoreListStore.Rules.IsEmpty;

        view.Filter = search.Length == 0 && !hiding
            ? null
            : item => item is DomainGroupViewModel domain
                      && !IsDomainHidden(domain)
                      && (search.Length == 0
                          || domain.Host.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || domain.Exchanges.Any(x => x.Client.Contains(search, StringComparison.OrdinalIgnoreCase)
                                                       || x.Path.Contains(search, StringComparison.OrdinalIgnoreCase)));

        // Requests from a hidden app disappear from under their domain too, not just from the grid.
        foreach (var domain in Domains)
            ApplyGroupFilter(domain, hiding);
    }

    private static void ApplyGroupFilter(DomainGroupViewModel domain, bool hiding)
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(domain.Exchanges);
        view.Filter = hiding ? item => item is HttpExchangeRowViewModel row && !IsExchangeHidden(row) : null;
    }

    private void ApplyFilter()
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Exchanges);
        var hosts = _domainFilter.Count == 0 ? null : _domainFilter.ToHashSet(StringComparer.OrdinalIgnoreCase);
        string search = SearchText.Trim();
        bool hiding = !IgnoreListStore.Rules.IsEmpty;
        bool bodies = SearchBodies;
        bool errorsOnly = ErrorsOnly;

        var clients = _clientFilter.Count == 0 ? null : _clientFilter.ToHashSet(StringComparer.OrdinalIgnoreCase);
        bool browserOnly = BrowserOnly;

        view.Filter = hosts is null && clients is null && search.Length == 0 && !hiding && !errorsOnly && !browserOnly
            ? null
            : item => item is HttpExchangeRowViewModel row
                      && !IsExchangeHidden(row)
                      && (hosts is null || hosts.Contains(row.Host))
                      && (clients is null || clients.Contains(row.Client))
                      && (!browserOnly || ClientRowViewModel.LooksLikeBrowser(row.Client))
                      && (!errorsOnly || IsFailure(row))
                      && (search.Length == 0
                          || row.Url.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || row.Method.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || row.Status.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || row.Client.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || (bodies && row.SearchableBody.Contains(search, StringComparison.OrdinalIgnoreCase)));

        UpdateFilterSummary();
    }

    /// <summary>What "errors only" means: the server said no, or there was no answer at all.</summary>
    private static bool IsFailure(HttpExchangeRowViewModel row) =>
        row.Exchange.State == ExchangeState.Failed || row.Exchange.StatusCode >= 400;

    private void UpdateFilterSummary()
    {
        if (!IsFiltered)
        {
            FilterSummary = "";
            return;
        }

        int shown = System.Windows.Data.CollectionViewSource.GetDefaultView(Exchanges) is System.Windows.Data.ListCollectionView list
            ? list.Count
            : Exchanges.Count;
        FilterSummary = Loc.Format("Filter_ShowingOf", shown, Exchanges.Count);
    }

    [ObservableProperty] private bool _isCaInstalled;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleSystemProxyCommand))]
    private bool _isSystemProxyEnabled;

    public string CaThumbprint => _ca.Thumbprint;

    public ProxyViewModel()
    {
        StatusMessage = Loc.Get("Proxy_Status_Stopped");
        IsCaInstalled = SafeCall(() => _ca.IsInstalledForCurrentUser(), fallback: false);
        IsSystemProxyEnabled = SafeCall(WindowsProxySettings.IsEnabled, fallback: false);
        RecoverOrphanedSystemProxy();

        _drainTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(150) };
        _drainTimer.Tick += (_, _) => Drain();
        _drainTimer.Start();

        // Shared with the packet page and persisted, so it may already hide things at launch.
        IgnoreListStore.Rules.Changed += OnIgnoreRulesChanged;
        ApplyFilter();
        ApplyDomainFilter();
        ApplyDomainSort();
    }


    /// <summary>
    /// Undoes a system-proxy setting left pointing at this app after it died without cleaning
    /// up - killed, crashed, or the machine lost power while it was running.
    ///
    /// Windows then routes everything into a port nobody is listening on, and the machine looks
    /// like it has no internet at all: browsers, chat apps, updaters, all of it. Nobody would
    /// connect that to a packet tool that is no longer even open, so this checks at startup and
    /// puts the setting back.
    ///
    /// Deliberately narrow: only a loopback proxy, and only when nothing is actually listening
    /// there. Someone else's proxy on this machine is none of our business.
    /// </summary>
    private void RecoverOrphanedSystemProxy()
    {
        if (!IsSystemProxyEnabled) return;

        string? server = SafeCall(WindowsProxySettings.CurrentProxyServer, fallback: null);
        if (server is null) return;

        string[] parts = server.Split(':');
        if (parts.Length != 2 || parts[0] is not ("127.0.0.1" or "localhost")) return;
        if (!int.TryParse(parts[1], out int port)) return;
        if (IsSomethingListeningOn(port)) return;

        try
        {
            WindowsProxySettings.Disable();
            IsSystemProxyEnabled = false;
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyRecovered", server);
            ToastService.Show(StatusMessage, "PlugDisconnected24");
        }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException)
        {
            // Cannot fix it from here; say so rather than pretend the setting is fine.
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyStale", server);
        }
    }

    private static bool IsSomethingListeningOn(int port)
    {
        try
        {
            return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpListeners()
                .Any(endPoint => endPoint.Port == port);
        }
        catch (System.Net.NetworkInformation.NetworkInformationException)
        {
            // Unable to tell - leave the setting alone rather than guess.
            return true;
        }
    }

    // A transparent port that is switched on but unusable would otherwise be skipped silently,
    // leaving the user wondering why redirected programs never show up.
    private bool CanStart() =>
        !IsRunning && IsPortValid && (!TransparentEnabled || (TransparentPort != 0 && TransparentPort != Port));

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void StartProxy()
    {
        var server = new ProxyServer(
            new ProxyOptions
            {
                Port = Port,
                TransparentPort = TransparentEnabled ? TransparentPort : 0,
                ResolveClientApplication = endPoint =>
                    ProcessPortMap.Shared.LookupTcpClient(endPoint) is { } owner
                        ? new ClientApplication(owner.Name, owner.ImagePath)
                        : null,
            },
            _ca);
        server.ExchangeStarted += (_, exchange) => _incoming.Enqueue(exchange);
        server.ExchangeUpdated += (_, exchange) => _incoming.Enqueue(exchange);
        // Null once WPF is shutting down; this arrives on a connection's own thread.
        server.ConnectionError += (_, message) =>
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(() => StatusMessage = message);

        try
        {
            server.Start();
            _server = server;
            IsRunning = true;

            // Saved once they are known to work, not on every keystroke: a port that failed to
            // bind is not the one to greet the next launch with.
            AppSettings.Update(settings =>
            {
                settings.ProxyPort = Port;
                settings.TransparentProxy = TransparentEnabled;
                if (TransparentEnabled) settings.TransparentPort = TransparentPort;
            });
            StatusMessage = TransparentEnabled
                ? Loc.Format("Proxy_Status_ListeningTransparent", Port, TransparentPort)
                : Loc.Format("Proxy_Status_Listening", Port);
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_FailedToStart", ex.Message);
        }

        StartProxyCommand.NotifyCanExecuteChanged();
        StopProxyCommand.NotifyCanExecuteChanged();
    }

    private bool CanStop() => IsRunning;

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void StopProxy()
    {
        _server?.Stop();
        _server = null;
        IsRunning = false;
        RestoreSystemProxy();
        StatusMessage = Loc.Get("Proxy_Status_Stopped");

        StartProxyCommand.NotifyCanExecuteChanged();
        StopProxyCommand.NotifyCanExecuteChanged();
    }

    /// <summary>Undoes our own system-proxy change so traffic isn't left pointed at a dead port.</summary>
    private void RestoreSystemProxy()
    {
        if (!_weEnabledSystemProxy) return;

        try
        {
            WindowsProxySettings.Disable();
            IsSystemProxyEnabled = false;
        }
        catch
        {
            // Nothing useful to say at shutdown; the user can turn it off in Windows settings.
        }
        finally
        {
            _weEnabledSystemProxy = false;
        }
    }

    // ---------------------------------------------------------------- one request at a time

    private readonly RequestReplayer _replayer = new();

    /// <summary>
    /// Ids for replayed requests. The proxy counts its own exchanges up from zero, so replays
    /// count down from below zero and the two can never collide in the row index.
    /// </summary>
    private long _nextReplayId;

    /// <summary>
    /// Sends the selected request again, straight to the origin, and drops the answer into the
    /// list next to the original. "Is it still broken?" without leaving the app or rebuilding
    /// the request by hand in a terminal.
    /// </summary>
    [RelayCommand]
    private async Task ReplayAsync(HttpExchangeRowViewModel? row)
    {
        if (row is null) return;

        StatusMessage = Loc.Format("Proxy_Replaying", row.Url);

        HttpExchange replay;
        try
        {
            replay = await _replayer.ReplayAsync(row.Exchange, Interlocked.Decrement(ref _nextReplayId));
        }
        catch (Exception ex)
        {
            // ReplayAsync turns network failures into failed exchanges; anything reaching here is
            // a request we could not even build (a URL the capture recorded malformed, say).
            StatusMessage = Loc.Format("Proxy_ReplayFailed", ex.Message);
            return;
        }

        _incoming.Enqueue(replay);
        Drain();

        if (_rowsById.TryGetValue(replay.Id, out var replayRow))
        {
            SelectedExchange = replayRow;
            SelectedDomain = _domainsByHost.GetValueOrDefault(replayRow.Host);
        }

        bool answered = replay.State == ExchangeState.ResponseReceived;
        StatusMessage = answered
            ? Loc.Format("Proxy_Replayed", replay.StatusCode ?? 0, replay.Duration?.TotalMilliseconds ?? 0)
            : Loc.Format("Proxy_ReplayFailed", replay.Error ?? "");
        ToastService.Show(StatusMessage, answered ? "ArrowRepeatAll24" : "Warning24");
    }

    /// <summary>Copies the request as a shell command, a PowerShell call or a fetch() snippet.</summary>
    [RelayCommand]
    private void CopyAs((HttpExchangeRowViewModel Row, string Format) request)
    {
        var exchange = request.Row.Exchange;
        string text = request.Format switch
        {
            "curl" => RequestExport.ToCurl(exchange),
            "powershell" => RequestExport.ToPowerShell(exchange),
            "fetch" => RequestExport.ToFetch(exchange),
            "url" => exchange.Url,
            "response" => request.Row.ResponseBodyText,
            _ => "",
        };

        bool copied = ClipboardService.TrySetText(text);
        StatusMessage = copied ? Loc.Get("Proxy_Copied") : Loc.Get("Proxy_CopyFailed");
        ToastService.Show(StatusMessage, copied ? "Copy24" : "Warning24");
    }

    /// <summary>
    /// Writes the response body to a file, decoded: what lands on disk is what the server meant,
    /// not the gzip it travelled as.
    /// </summary>
    [RelayCommand]
    private void SaveResponseBody(HttpExchangeRowViewModel? row)
    {
        if (row is null || row.Exchange.ResponseBody.Length == 0)
        {
            StatusMessage = Loc.Get("Proxy_NoBodyToSave");
            return;
        }

        var dialog = new SaveFileDialog { FileName = SuggestFileName(row), Filter = "All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;

        try
        {
            byte[] body = BodyFormatter.Decode(row.Exchange.ResponseHeaders, row.Exchange.ResponseBody);
            File.WriteAllBytes(dialog.FileName, body);
            StatusMessage = Loc.Format("Proxy_BodySaved", dialog.FileName, body.Length);
            ToastService.Show(StatusMessage, "Save24");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            StatusMessage = Loc.Format("Sessions_SaveFailed", ex.Message);
        }
    }

    /// <summary>The last path segment, or the host - whatever a person would have typed themselves.</summary>
    private static string SuggestFileName(HttpExchangeRowViewModel row)
    {
        string path = row.Exchange.PathAndQuery.Split('?')[0].TrimEnd('/');
        string name = path.Length == 0 ? row.Host : path[(path.LastIndexOf('/') + 1)..];
        if (name.Length == 0) name = row.Host;

        foreach (char invalid in Path.GetInvalidFileNameChars())
            name = name.Replace(invalid, '_');

        return name.Length == 0 ? "response" : name;
    }

    /// <summary>Opens the request's URL in the default browser - the GET you want to look at by eye.</summary>
    [RelayCommand]
    private void OpenInBrowser(HttpExchangeRowViewModel? row)
    {
        if (row is null || row.Exchange.Scheme is not ("http" or "https")) return;

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(row.Url) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            StatusMessage = Loc.Format("Proxy_OpenFailed", ex.Message);
        }
    }

    /// <summary>Saves the captured requests, bodies and all, as a named session.</summary>
    [RelayCommand]
    private void SaveSession()
    {
        if (Exchanges.Count == 0)
        {
            StatusMessage = Loc.Get("Sessions_NothingToSave");
            return;
        }

        try
        {
            var session = SessionService.Store.Create(
                Loc.Format("Sessions_DefaultProxyName", DateTime.Now.ToString("dd.MM HH:mm")),
                new SessionInfo
                {
                    Id = "", Name = "", Created = default,
                    Source = Loc.Format("Proxy_Status_Listening", Port),
                    RequestCount = Exchanges.Count,
                    HostCount = Domains.Count,
                });

            ProxySessionFile.Save(
                SessionService.Store.PathTo(session, SessionStore.RequestsFileName),
                Exchanges.Select(row => row.Exchange));

            StatusMessage = Loc.Format("Sessions_Saved", session.Name);
            SessionSaved?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            StatusMessage = Loc.Format("Sessions_SaveFailed", ex.Message);
        }
    }

    public event EventHandler? SessionSaved;

    /// <summary>Replaces the list with the requests from a saved session, for reading back.</summary>
    public void LoadSession(SessionInfo session)
    {
        ClearExchanges();

        var saved = ProxySessionFile.Load(SessionService.Store.PathTo(session, SessionStore.RequestsFileName));
        foreach (var exchange in saved)
            _incoming.Enqueue(exchange);

        Drain();
        StatusMessage = Loc.Format("Sessions_Opened", session.Name, saved.Count);
    }

    [RelayCommand]
    private void ClearExchanges()
    {
        SelectedDomain = null;
        Exchanges.Clear();
        _rowsById.Clear();
        Domains.Clear();
        _domainsByHost.Clear();
        Clients.Clear();
        _clientsByName.Clear();
        SelectedExchange = null;

        // The ticked domains and programs went with the list; their filters go with them.
        ResetDomainFilter();
        ResetClientFilter();
        ApplyFilter();
    }

    [RelayCommand]
    private void InstallRootCertificate()
    {
        try
        {
            _ca.InstallForCurrentUser();
            IsCaInstalled = true;
            StatusMessage = Loc.Get("Proxy_Status_CertInstalled");
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_CertInstallFailed", ex.Message);
        }
    }

    [RelayCommand]
    private void UninstallRootCertificate()
    {
        try
        {
            _ca.UninstallForCurrentUser();
            IsCaInstalled = false;
            StatusMessage = Loc.Get("Proxy_Status_CertRemoved");
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_CertRemoveFailed", ex.Message);
        }
    }

    [RelayCommand]
    private void ExportRootCertificate()
    {
        var dialog = new SaveFileDialog { Filter = "PEM certificate (*.pem)|*.pem", FileName = "loupe-root-ca.pem" };
        if (dialog.ShowDialog() != true) return;

        File.WriteAllText(dialog.FileName, _ca.ExportPublicCertificatePem());
        StatusMessage = Loc.Format("Proxy_Status_CertExported", dialog.FileName);
    }

    /// <summary>
    /// One switch for the system proxy rather than two buttons: it is a single piece of state
    /// with two directions, and a toolbar that shows both at once has to explain which applies.
    ///
    /// Turning it on needs the proxy to be listening. Pointing Windows at a port with nothing
    /// behind it takes the whole machine offline, and the person it happens to has no reason to
    /// connect that to a button in a packet tool.
    /// </summary>
    private bool CanToggleSystemProxy() => IsRunning || IsSystemProxyEnabled;

    [RelayCommand(CanExecute = nameof(CanToggleSystemProxy))]
    private void ToggleSystemProxy()
    {
        if (IsSystemProxyEnabled) DisableSystemProxy();
        else EnableSystemProxy();
    }

    [RelayCommand]
    private void EnableSystemProxy()
    {
        try
        {
            WindowsProxySettings.Enable("127.0.0.1", Port);
            IsSystemProxyEnabled = true;
            _weEnabledSystemProxy = true;
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyEnabled", Port);
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyEnableFailed", ex.Message);
        }
    }

    [RelayCommand]
    private void DisableSystemProxy()
    {
        try
        {
            WindowsProxySettings.Disable();
            IsSystemProxyEnabled = false;
            _weEnabledSystemProxy = false;
            StatusMessage = Loc.Get("Proxy_Status_SystemProxyDisabled");
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyDisableFailed", ex.Message);
        }
    }

    private void Drain()
    {
        int processed = 0;
        var touchedDomains = new HashSet<DomainGroupViewModel>();

        while (processed < DrainBatchSize && _incoming.TryDequeue(out var exchange))
        {
            if (_rowsById.TryGetValue(exchange.Id, out var row))
            {
                // Updated in place by the proxy as the response arrives - the row and its
                // domain's totals both need to re-read it.
                row.Refresh();
                if (_domainsByHost.TryGetValue(row.Host, out var owner)) touchedDomains.Add(owner);
            }
            else
            {
                row = new HttpExchangeRowViewModel(exchange);
                _rowsById[exchange.Id] = row;
                Exchanges.Add(row);
                GroupFor(row.Host).Add(row);
            }

            TrackClient(row);
            processed++;
        }

        foreach (var domain in touchedDomains)
            domain.Recount();

        if (processed > 0 && (IsFiltered || HasHidden)) UpdateFilterSummary();

        // A domain's hidden state depends on which apps have used it, which only settles as its
        // requests arrive. Re-filter the sidebar when that actually flips, not on every tick -
        // a TreeView refresh is visible.
        if (processed > 0 && HasHidden)
        {
            var nowHidden = Domains.Where(IsDomainHidden).Select(d => d.Host).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!nowHidden.SetEquals(_hiddenDomains))
            {
                _hiddenDomains = nowHidden;
                System.Windows.Data.CollectionViewSource.GetDefaultView(Domains).Refresh();
            }
        }

        while (Exchanges.Count > MaxExchanges)
        {
            var oldest = Exchanges[0];
            Exchanges.RemoveAt(0);
            _rowsById.Remove(oldest.Id);

            if (!_domainsByHost.TryGetValue(oldest.Host, out var domain)) continue;

            domain.Exchanges.Remove(oldest);
            if (domain.Exchanges.Count == 0)
            {
                if (SelectedDomain == domain) SelectedDomain = null;

                // An evicted domain can't be unticked any more, so it must stop filtering.
                if (_domainFilter.Remove(oldest.Host))
                {
                    ApplyFilter();
                    OnPropertyChanged(nameof(IsFiltered));
                    OnPropertyChanged(nameof(FilterScope));
                }

                Domains.Remove(domain);
                _domainsByHost.Remove(oldest.Host);
            }
            else
            {
                domain.Recount();
            }
        }
    }

    /// <summary>
    /// Keeps the program list in step with the requests. Counted rather than incremented for the
    /// same reason the domains are: an exchange is updated in place as its response arrives, so
    /// its size is not final when the row first appears.
    /// </summary>
    private void TrackClient(HttpExchangeRowViewModel row)
    {
        string name = row.Client;
        if (name.Length == 0) name = Loc.Get("Proxy_Client_Unknown");

        if (!_clientsByName.TryGetValue(name, out var client))
        {
            client = new ClientRowViewModel(name, row.Exchange.Client?.ImagePath);
            client.PropertyChanged += OnClientCheckedChanged;
            _clientsByName[name] = client;
            Clients.Add(client);
            ApplyClientFilter();
        }

        client.RequestCount = Exchanges.Count(e => string.Equals(
            e.Client.Length == 0 ? Loc.Get("Proxy_Client_Unknown") : e.Client, name, StringComparison.OrdinalIgnoreCase));
        client.TotalBytes = Exchanges
            .Where(e => string.Equals(e.Client.Length == 0 ? Loc.Get("Proxy_Client_Unknown") : e.Client, name, StringComparison.OrdinalIgnoreCase))
            .Sum(e => (long)e.ResponseSize);
        client.LastActivity = row.Exchange.StartTime;
    }

    /// <summary>Returns the sidebar group for a host, creating it in alphabetical position.</summary>
    private DomainGroupViewModel GroupFor(string host)
    {
        if (_domainsByHost.TryGetValue(host, out var existing)) return existing;

        var group = new DomainGroupViewModel(host, _favicons);
        _domainsByHost[host] = group;

        // Alphabetical and stable: a list that reordered itself by traffic would move the
        // domain out from under the pointer while you were reading it.
        int index = 0;
        while (index < Domains.Count
               && string.CompareOrdinal(Domains[index].Host, host) < 0)
        {
            index++;
        }

        group.PropertyChanged += OnDomainCheckedChanged;
        Domains.Insert(index, group);
        ApplyGroupFilter(group, hiding: !IgnoreListStore.Rules.IsEmpty);
        return group;
    }

    private static T SafeCall<T>(Func<T> action, T fallback)
    {
        try { return action(); } catch { return fallback; }
    }

    public void Dispose()
    {
        _drainTimer.Stop();
        IgnoreListStore.Rules.Changed -= OnIgnoreRulesChanged;
        _server?.Stop();
        RestoreSystemProxy();
        _favicons.Dispose();
        _replayer.Dispose();
    }
}
