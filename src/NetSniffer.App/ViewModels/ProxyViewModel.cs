using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NetSniffer.App.Localization;
using NetSniffer.App.Services;
using NetSniffer.Capture.Processes;
using NetSniffer.Proxy;
using NetSniffer.Proxy.Ca;
using NetSniffer.Proxy.Http;

namespace NetSniffer.App.ViewModels;

public partial class ProxyViewModel : ObservableObject, IDisposable
{
    private const int MaxExchanges = 50_000;
    private const int DrainBatchSize = 500;

    private readonly ConcurrentQueue<HttpExchange> _incoming = new();
    private readonly Dictionary<long, HttpExchangeRowViewModel> _rowsById = [];
    private readonly DispatcherTimer _drainTimer;
    private readonly RootCertificateAuthority _ca = new();

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
    private readonly FaviconService _favicons = new();

    [ObservableProperty] private int _port = 8080;

    /// <summary>
    /// Second listener that takes raw connections with no CONNECT line, routing by TLS SNI or
    /// Host header. This is the answer to "it only captures my browser": programs that ignore
    /// the Windows proxy setting can be pointed here instead and are intercepted the same way.
    /// </summary>
    [ObservableProperty] private int _transparentPort = 8443;

    [ObservableProperty] private bool _transparentEnabled;
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private HttpExchangeRowViewModel? _selectedExchange;
    /// <summary>Domain picked in the sidebar; narrows the request list to it.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private DomainGroupViewModel? _selectedDomain;

    /// <summary>Search over URL, method, status and the sending app.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private string _searchText = "";

    [ObservableProperty] private string _filterSummary = "";

    public bool IsFiltered => SelectedDomain is not null || !string.IsNullOrWhiteSpace(SearchText);

    partial void OnSelectedDomainChanged(DomainGroupViewModel? value) => ApplyFilter();

    partial void OnSearchTextChanged(string value) => ApplyFilter(); // request lists stay small enough

    [RelayCommand]
    private void ClearFilter()
    {
        SelectedDomain = null;
        SearchText = "";
        ApplyFilter();
    }

    // ---------------------------------------------------------------- hiding & domain search

    /// <summary>Search over the domain sidebar: host name, or an app that talked to it.</summary>
    [ObservableProperty] private string _domainSearchText = "";

    partial void OnDomainSearchTextChanged(string value) => ApplyDomainFilter();

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
        string? host = SelectedDomain?.Host;
        string search = SearchText.Trim();
        bool hiding = !IgnoreListStore.Rules.IsEmpty;

        view.Filter = host is null && search.Length == 0 && !hiding
            ? null
            : item => item is HttpExchangeRowViewModel row
                      && !IsExchangeHidden(row)
                      && (host is null || string.Equals(row.Host, host, StringComparison.OrdinalIgnoreCase))
                      && (search.Length == 0
                          || row.Url.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || row.Method.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || row.Status.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || row.Client.Contains(search, StringComparison.OrdinalIgnoreCase));

        UpdateFilterSummary();
    }

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
    [ObservableProperty] private bool _isSystemProxyEnabled;

    public string CaThumbprint => _ca.Thumbprint;

    public ProxyViewModel()
    {
        StatusMessage = Loc.Get("Proxy_Status_Stopped");
        IsCaInstalled = SafeCall(() => _ca.IsInstalledForCurrentUser(), fallback: false);
        IsSystemProxyEnabled = SafeCall(WindowsProxySettings.IsEnabled, fallback: false);

        _drainTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(150) };
        _drainTimer.Tick += (_, _) => Drain();
        _drainTimer.Start();

        // Shared with the packet page and persisted, so it may already hide things at launch.
        IgnoreListStore.Rules.Changed += OnIgnoreRulesChanged;
        ApplyFilter();
        ApplyDomainFilter();
    }

    private bool CanStart() => !IsRunning;

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
        server.ConnectionError += (_, message) => System.Windows.Application.Current.Dispatcher.BeginInvoke(() => StatusMessage = message);

        try
        {
            server.Start();
            _server = server;
            IsRunning = true;
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

    [RelayCommand]
    private void ClearExchanges()
    {
        SelectedDomain = null;
        Exchanges.Clear();
        _rowsById.Clear();
        Domains.Clear();
        _domainsByHost.Clear();
        SelectedExchange = null;
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
        var dialog = new SaveFileDialog { Filter = "PEM certificate (*.pem)|*.pem", FileName = "netsniffer-root-ca.pem" };
        if (dialog.ShowDialog() != true) return;

        File.WriteAllText(dialog.FileName, _ca.ExportPublicCertificatePem());
        StatusMessage = Loc.Format("Proxy_Status_CertExported", dialog.FileName);
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
                Domains.Remove(domain);
                _domainsByHost.Remove(oldest.Host);
            }
            else
            {
                domain.Recount();
            }
        }
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
    }
}
