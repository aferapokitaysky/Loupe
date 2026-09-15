using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NetSniffer.App.Localization;
using NetSniffer.Capture;
using NetSniffer.Capture.Processes;
using NetSniffer.Core.IO;
using NetSniffer.App.Services;
using NetSniffer.Core.Model;
using NetSniffer.Core.Naming;
using NetSniffer.Core.Parsing;
using NetSniffer.Core.Sessions;
using NetSniffer.Core.Tcp;

namespace NetSniffer.App.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    /// <summary>
    /// How many rows the grid keeps. Every row pins the packet's raw bytes, so this is really a
    /// memory setting: at ~1 KB a frame, 50k rows is around 50 MB. The old 250k quietly grew to
    /// a third of a gigabyte on a busy link.
    /// </summary>
    private const int MaxDisplayedPackets = 50_000;

    /// <summary>
    /// Ceiling on packets waiting to be parsed. A gigabit link can out-run any UI; without a
    /// bound the queue is where the memory goes. Past this, packets are dropped and counted -
    /// a visibly dropped count is honest, silently eating all the RAM is not.
    /// </summary>
    private const int MaxQueuedPackets = 200_000;

    private const int DrainBudgetMs = 12;

    /// <summary>Rows appended to the grid per tick. Beyond this nobody can read them anyway, and
    /// every row costs layout; the counters and the hosts panel still see every packet.</summary>
    private const int MaxRowsPerTick = 400;

    private readonly ConcurrentQueue<CapturedPacket> _incoming = new();
    private readonly ConcurrentQueue<PacketRowViewModel> _parsed = new();
    private readonly SemaphoreSlim _parseSignal = new(0);
    private readonly CancellationTokenSource _parseCancellation = new();
    private long _queuedCount;
    private long _droppedCount;
    private readonly DispatcherTimer _drainTimer;
    private readonly TcpStreamReassembler _reassembler = new();
    private readonly HostNameRegistry _names = new();
    private readonly HostTrafficTracker _hosts = new(LocalAddresses(), ResolveLocalProcess);
    private readonly FaviconService _favicons = new();
    private readonly Dictionary<string, HostRowViewModel> _hostRows = [];

    private CaptureSession? _session;
    private DateTimeOffset _captureStart;

    public ObservableCollection<CaptureDeviceInfo> Adapters { get; } = [];
    public ObservableCollection<PacketRowViewModel> Packets { get; } = [];

    /// <summary>
    /// Remote hosts seen so far, newest traffic first. Rebuilt once per drain tick rather than
    /// per packet: on a busy link the packet grid is unreadable, but this list stays calm.
    /// </summary>
    public ObservableCollection<HostRowViewModel> Hosts { get; } = [];

    public string HostsCountText => Loc.Format("Pkt_StatusBar_Hosts", Hosts.Count);

    /// <summary>
    /// Raised once per drain tick after a batch of packets has been appended - never from
    /// inside a CollectionChanged notification, so a handler may safely touch the grid.
    /// </summary>
    public event EventHandler? PacketsAppended;

    [ObservableProperty] private CaptureDeviceInfo? _selectedAdapter;
    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private bool _isCapturing;
    [ObservableProperty] private bool _autoScroll = true;

    /// <summary>Fold runs of identical packets into one counted row. On by default: a bulk
    /// transfer is otherwise hundreds of lines that differ only in sequence number.</summary>
    [ObservableProperty] private bool _collapseRepeats = true;

    /// <summary>Host picked in the hosts panel; narrows the packet list to its traffic.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private HostRowViewModel? _selectedHost;

    /// <summary>Free-text search over endpoints, domains, protocol, program and summary.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private string _searchText = "";

    [ObservableProperty] private string _filterSummary = "";

    public bool IsFiltered => SelectedHost is not null || !string.IsNullOrWhiteSpace(SearchText);
    [ObservableProperty] private PacketRowViewModel? _selectedPacket;
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool _isCaptureEngineAvailable = true;

    // Npcap-setup overlay state, shown over the packet list while the engine is missing.
    [ObservableProperty] private bool _npcapBusy;
    [ObservableProperty] private bool _npcapCanRetry;
    [ObservableProperty] private string _npcapStatus = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PacketsCountText))]
    private long _totalPackets;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BytesCountText))]
    private long _totalBytes;

    /// <summary>Packets the capture engine handed over but that were dropped because the parser
    /// was behind. Surfaced rather than hidden - a silent gap in a capture is a trap.</summary>
    public long DroppedPackets => Interlocked.Read(ref _droppedCount);

    public bool HasDropped => DroppedPackets > 0;
    public string DroppedText => Loc.Format("Pkt_StatusBar_Dropped", DroppedPackets);

    public string PacketsCountText => Loc.Format("Pkt_StatusBar_Packets", TotalPackets);
    public string BytesCountText => Loc.Format("Pkt_StatusBar_Bytes", TotalBytes);

    public MainViewModel()
    {
        StatusMessage = Loc.Get("Pkt_Status_Ready");

        // The status-bar counters bake their label into the string, so they'd keep the old
        // language until the next packet arrived. Re-read them when the language changes.
        LocalizationService.LanguageChanged += OnLanguageChanged;

        // Rules persist across launches, so they may already hide something before any packet.
        IgnoreListStore.Rules.Changed += OnIgnoreRulesChanged;
        ApplyFilter();
        ApplyHostFilter();

        _drainTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(150),
        };
        _drainTimer.Tick += (_, _) => DrainIncomingPackets();
        _drainTimer.Start();

        // Below normal priority: the UI thread must always win. Background so it can't keep
        // the process alive if Dispose is missed.
        _parseThread = new Thread(ParseLoop)
        {
            IsBackground = true,
            Name = "NetSniffer.Parse",
            Priority = ThreadPriority.BelowNormal,
        };
        _parseThread.Start();

        RefreshAdapters();

        // No Npcap on this machine? Don't make the user hunt for a button - offer to
        // fetch and run the official installer right away. This only kicks off the same
        // download flow the manual "retry" uses; it never installs silently (the official
        // installer shows its own wizard and Windows shows its own elevation prompt).
        if (!IsCaptureEngineAvailable)
            _ = EnsureNpcapAsync();
    }

    [RelayCommand]
    private void RefreshAdapters()
    {
        try
        {
            // Clearing the collection makes the bound ComboBox null out SelectedAdapter, so
            // remember the user's pick by name and restore it instead of silently jumping
            // back to the default on every refresh.
            string? previouslySelected = SelectedAdapter?.Name;

            Adapters.Clear();
            foreach (var device in CaptureDeviceManager.ListDevices())
                Adapters.Add(device);

            IsCaptureEngineAvailable = true;
            SelectedAdapter = Adapters.FirstOrDefault(a => a.Name == previouslySelected)
                              ?? CaptureDeviceManager.PickDefault(Adapters);
            StatusMessage = Adapters.Count == 0
                ? Loc.Get("Pkt_Status_NoAdapters")
                : Loc.Format("Pkt_Status_AdaptersFound", Adapters.Count);
        }
        catch (CaptureException ex)
        {
            StatusMessage = ex.Message;
        }
        catch (DllNotFoundException)
        {
            // NetSniffer.Native.dll (or the wpcap.dll it links against) isn't loadable -
            // almost always means the Npcap runtime isn't installed yet. Degrade to an
            // empty adapter list with a clear next step rather than crashing startup.
            IsCaptureEngineAvailable = false;
            StatusMessage = Loc.Get("Pkt_Status_EngineMissingNpcap");
        }
        catch (BadImageFormatException)
        {
            IsCaptureEngineAvailable = false;
            StatusMessage = Loc.Get("Pkt_Status_EngineBadImage");
        }
    }

    [RelayCommand]
    private Task RetryNpcap() => EnsureNpcapAsync();

    private async Task EnsureNpcapAsync()
    {
        if (NpcapBusy) return;

        NpcapBusy = true;
        NpcapCanRetry = false;

        var progress = new Progress<NpcapInstallStage>(stage => NpcapStatus = stage switch
        {
            NpcapInstallStage.Downloading => Loc.Get("Pkt_Status_NpcapDownloading"),
            NpcapInstallStage.Launching => Loc.Get("Pkt_Status_NpcapLaunching"),
            _ => NpcapStatus,
        });

        try
        {
            await NpcapInstaller.RunInstallerAsync(progress);
            RefreshAdapters();
            if (!IsCaptureEngineAvailable)
            {
                NpcapStatus = Loc.Get("Pkt_Status_NpcapInstallCancelled");
                NpcapCanRetry = true;
            }
        }
        catch (Exception ex)
        {
            NpcapStatus = Loc.Format("Pkt_Status_NpcapInstallFailed", ex.Message);
            NpcapCanRetry = true;
        }
        finally
        {
            NpcapBusy = false;
        }
    }

    private bool CanStart() => !IsCapturing && SelectedAdapter is not null;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void StartCapture()
    {
        if (SelectedAdapter is null) return;

        _session = new CaptureSession(SelectedAdapter);
        _session.PacketArrived += (_, e) => Enqueue(e.Packet);
        // Application.Current is null once WPF has shut down, and this fires from the capture
        // thread - an NRE there is an unhandled exception on a non-UI thread.
        _session.Stopped += (_, e) => Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            IsCapturing = false;
            StatusMessage = e.ErrorReason is null
                ? Loc.Get("Pkt_Status_Stopped")
                : Loc.Format("Pkt_Status_StoppedWithError", e.ErrorReason);
            StartCaptureCommand.NotifyCanExecuteChanged();
            StopCaptureCommand.NotifyCanExecuteChanged();
        });

        try
        {
            _captureStart = DateTimeOffset.Now;
            _session.Start(string.IsNullOrWhiteSpace(FilterText) ? null : FilterText);
            IsCapturing = true;
            StatusMessage = Loc.Format("Pkt_Status_Capturing", SelectedAdapter.Description);
        }
        catch (CaptureException ex)
        {
            StatusMessage = ex.Message;
            _session.Dispose();
            _session = null;
        }

        StartCaptureCommand.NotifyCanExecuteChanged();
        StopCaptureCommand.NotifyCanExecuteChanged();
    }

    private bool CanStop() => IsCapturing;

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void StopCapture() => _session?.Stop();

    [RelayCommand]
    private void ClearPackets()
    {
        // Drop rows the parser already produced too, or they'd stream straight back in.
        while (_parsed.TryDequeue(out _)) { }

        // The selected host is about to disappear from the list; drop the filter with it rather
        // than leave an empty grid filtered on a host nobody can see any more.
        SelectedHost = null;

        Packets.Clear();
        Hosts.Clear();
        _hostRows.Clear();
        _reassembler.Clear();
        _hosts.Clear();

        // The name registry deliberately survives a clear: names learned from DNS answers
        // earlier in the session still describe the addresses that keep showing up, and those
        // answers won't be repeated until the TTL expires.
        Interlocked.Exchange(ref _livePackets, 0);
        Interlocked.Exchange(ref _liveBytes, 0);
        Interlocked.Exchange(ref _droppedCount, 0);
        TotalPackets = 0;
        TotalBytes = 0;
        SelectedPacket = null;
        OnPropertyChanged(nameof(HostsCountText));
        OnPropertyChanged(nameof(DroppedText));
        OnPropertyChanged(nameof(HasDropped));
    }

    [RelayCommand]
    private void SaveCapture()
    {
        var dialog = new SaveFileDialog { Filter = "pcap files (*.pcap)|*.pcap", FileName = "capture.pcap" };
        if (dialog.ShowDialog() != true) return;

        // SelectMany over AllPackets, not one frame per row: rows that folded a run of identical
        // packets still write every frame, so a saved capture matches the wire rather than the grid.
        var frames = Packets
            .SelectMany(row => row.AllPackets)
            .Select(p => new CapturedPacket(p.Number, p.Timestamp, p.RawData, p.OriginalLength))
            .ToList();

        PcapFile.Write(dialog.FileName, frames);
        StatusMessage = Loc.Format("Pkt_Status_Saved", frames.Count, dialog.FileName);
    }

    /// <summary>
    /// Saves everything on screen as a named session - the capture as an ordinary .pcap, so it
    /// also opens in Wireshark, plus what it was and how big it was.
    /// </summary>
    [RelayCommand]
    private void SaveSession()
    {
        var frames = Packets
            .SelectMany(row => row.AllPackets)
            .Select(p => new CapturedPacket(p.Number, p.Timestamp, p.RawData, p.OriginalLength))
            .ToList();

        if (frames.Count == 0)
        {
            StatusMessage = Loc.Get("Sessions_NothingToSave");
            return;
        }

        try
        {
            var session = SessionService.Store.Create(
                Loc.Format("Sessions_DefaultName", DateTime.Now.ToString("dd.MM HH:mm")),
                new SessionInfo
                {
                    Id = "", Name = "", Created = default,
                    Source = SelectedAdapter?.Description,
                    PacketCount = frames.Count,
                    ByteCount = TotalBytes,
                    HostCount = Hosts.Count,
                });

            PcapFile.Write(SessionService.Store.PathTo(session, SessionStore.CaptureFileName), frames);
            StatusMessage = Loc.Format("Sessions_Saved", session.Name);
            SessionSaved?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            StatusMessage = Loc.Format("Sessions_SaveFailed", ex.Message);
        }
    }

    /// <summary>Lets the window refresh the sessions list without it polling the disk.</summary>
    public event EventHandler? SessionSaved;

    [RelayCommand]
    private void OpenCapture()
    {
        var dialog = new OpenFileDialog { Filter = "pcap files (*.pcap)|*.pcap" };
        if (dialog.ShowDialog() != true) return;

        LoadCaptureFile(dialog.FileName);
    }

    /// <summary>
    /// Reads a .pcap into the pipeline off the UI thread. A capture file can be gigabytes, so
    /// reading it inline froze the window, and pushing it through the same bounded queue as a
    /// live adapter silently dropped everything past the cap - a file has no reason to lose
    /// packets, so this one waits for room instead.
    /// </summary>
    public void LoadCaptureFile(string path)
    {
        // Mixing a file into a running capture would interleave two unrelated timelines.
        if (IsCapturing) StopCapture();

        ClearPackets();
        _captureStart = DateTimeOffset.Now;
        StatusMessage = Loc.Format("Pkt_Status_Loading", Path.GetFileName(path));

        var token = _parseCancellation.Token;
        Task.Run(() =>
        {
            long count = 0;
            string message;

            try
            {
                foreach (var captured in PcapFile.Read(path))
                {
                    if (token.IsCancellationRequested) return;

                    // Backpressure rather than dropping: the parser is never far behind.
                    while (Interlocked.Read(ref _queuedCount) >= MaxQueuedPackets && !token.IsCancellationRequested)
                        Thread.Sleep(5);

                    Enqueue(captured);
                    count++;
                }

                message = Loc.Format("Pkt_Status_Loaded", Path.GetFileName(path));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
                                           or ArgumentException or NotSupportedException)
            {
                // A truncated or foreign file: keep whatever parsed and say what happened.
                message = Loc.Format("Pkt_Status_LoadFailed", ex.Message);
            }

            Application.Current?.Dispatcher.BeginInvoke(() => StatusMessage = message);
        }, token);
    }

    /// <summary>
    /// Hands a frame to the parser thread. Called straight from the capture callback, so it does
    /// as little as possible: a bounded enqueue and a signal.
    /// </summary>
    private void Enqueue(CapturedPacket captured)
    {
        if (_disposed) return; // a capture callback can outlive the view model by a moment

        if (Interlocked.Read(ref _queuedCount) >= MaxQueuedPackets)
        {
            Interlocked.Increment(ref _droppedCount);
            return;
        }

        Interlocked.Increment(ref _queuedCount);
        _incoming.Enqueue(captured);

        // The parser drains the whole queue per wake-up, so one spare release is enough to
        // guarantee it looks again; letting the count run up would just spin it.
        try
        {
            if (_parseSignal.CurrentCount == 0) _parseSignal.Release();
        }
        catch (ObjectDisposedException)
        {
            // Raced with shutdown. The packet is already queued and simply won't be parsed.
        }
    }

    /// <summary>
    /// Parses captured frames off the UI thread. Dissection, reassembly and the name and host
    /// rollups all happen here; the UI thread only ever appends already-finished rows. Doing
    /// this work in the dispatcher tick was what made the window stutter on a busy link.
    /// </summary>
    private void ParseLoop()
    {
        var token = _parseCancellation.Token;

        while (!token.IsCancellationRequested)
        {
            try
            {
                _parseSignal.Wait(token);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException)
            {
                return; // shutting down
            }

            while (_incoming.TryDequeue(out var captured))
            {
                Interlocked.Decrement(ref _queuedCount);

                ParsedPacket parsed;
                try
                {
                    parsed = PacketParser.Parse(captured);
                }
                catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException)
                {
                    // A dissector bug must never take the capture down with it.
                    continue;
                }

                _reassembler.Ingest(parsed);
                _names.Ingest(parsed);
                _hosts.Ingest(parsed, _names);

                Interlocked.Add(ref _liveBytes, parsed.OriginalLength);
                Interlocked.Increment(ref _livePackets);

                _parsed.Enqueue(new PacketRowViewModel(parsed, _captureStart, _names));
            }
        }
    }

    private long _livePackets;
    private long _liveBytes;

    private void DrainIncomingPackets()
    {
        // Counters come from the parser thread and cover every packet, including the ones whose
        // rows are skipped below - the totals must match the wire, not the grid.
        long packets = Interlocked.Read(ref _livePackets);
        long bytes = Interlocked.Read(ref _liveBytes);
        if (packets != TotalPackets) TotalPackets = packets;
        if (bytes != TotalBytes) TotalBytes = bytes;

        var budget = Stopwatch.StartNew();
        int appended = 0;
        int namesBefore = _names.Count;

        while (appended < MaxRowsPerTick
               && budget.ElapsedMilliseconds < DrainBudgetMs
               && _parsed.TryDequeue(out var row))
        {
            // Consecutive packets of the same shape collapse into one row with a count. A
            // bulk transfer is hundreds of identical lines; as one "x420" row it is readable,
            // and the row still opens the first packet of the run for dissection.
            if (CollapseRepeats && Packets.Count > 0 && Packets[^1].TryCollapse(row))
                continue;

            Packets.Add(row);
            appended++;
        }

        // Anything still queued past the retention window is dropped rather than displayed:
        // scrolling 20,000 rows through the grid to throw them away costs more than it's worth.
        if (_parsed.Count > MaxDisplayedPackets)
        {
            while (_parsed.Count > MaxDisplayedPackets / 2 && _parsed.TryDequeue(out _)) { }
        }

        if (HasDropped)
        {
            OnPropertyChanged(nameof(DroppedPackets));
            OnPropertyChanged(nameof(DroppedText));
            OnPropertyChanged(nameof(HasDropped));
        }

        if (appended == 0) return;

        while (Packets.Count > MaxDisplayedPackets)
            Packets.RemoveAt(0);

        RefreshHosts();
        if (IsFiltered || HasHidden) UpdateFilterSummary();

        // A name usually turns up after the first packets to an address, so rows already on
        // screen would otherwise keep showing the bare IP. Only the tail is refreshed: those
        // are the rows anyone can still see, and sweeping 50k of them per tick is what turned
        // a new domain into a visible hitch.
        if (_names.Count != namesBefore)
        {
            for (int i = Math.Max(0, Packets.Count - 500); i < Packets.Count; i++)
                Packets[i].RefreshNames();
        }

        PacketsAppended?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Mirrors the tracker into the bound collection, updating rows in place so the list doesn't
    /// flicker or lose the user's selection, and keeping it ordered by traffic volume.
    /// </summary>
    private void RefreshHosts()
    {
        foreach (var host in _hosts.Snapshot())
        {
            string key = host.Address.ToString();
            if (_hostRows.TryGetValue(key, out var existing))
            {
                existing.Update(host);
                continue;
            }

            var row = new HostRowViewModel(host, _favicons);
            _hostRows[key] = row;
            Hosts.Add(row);
        }

        // Re-sort only when the order actually changed: moving items in an ObservableCollection
        // is visible to the user, so doing it every tick would make the list jump constantly.
        var ordered = Hosts.OrderByDescending(h => h.Bytes).ToList();
        for (int i = 0; i < ordered.Count; i++)
        {
            int current = Hosts.IndexOf(ordered[i]);
            if (current != i) Hosts.Move(current, i);
        }

        OnPropertyChanged(nameof(HostsCountText));
    }

    // ---------------------------------------------------------------- filtering

    private DispatcherTimer? _searchDebounce;

    partial void OnSelectedHostChanged(HostRowViewModel? value) => ApplyFilter();

    /// <summary>Typing re-filters 50k rows; wait for a pause instead of doing it per keystroke.</summary>
    partial void OnSearchTextChanged(string value)
    {
        _searchDebounce ??= CreateSearchDebounce();
        _searchDebounce.Stop();
        _searchDebounce.Start();
    }

    private DispatcherTimer CreateSearchDebounce()
    {
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(220) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            ApplyFilter();
        };
        return timer;
    }

    [RelayCommand]
    private void ClearFilter()
    {
        SelectedHost = null;
        SearchText = "";
        _searchDebounce?.Stop();
        ApplyFilter();
    }

    /// <summary>
    /// Filters the grid's view rather than the collection: the capture itself (counters, saved
    /// .pcap, the folding of repeats) keeps seeing every packet, only what is shown narrows.
    /// </summary>
    private void ApplyFilter()
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Packets);
        var host = SelectedHost?.AddressValue;
        string search = SearchText.Trim();
        var rules = IgnoreListStore.Rules;

        view.Filter = host is null && search.Length == 0 && rules.IsEmpty
            ? null // no predicate at all: nothing to evaluate per row
            : item => item is PacketRowViewModel row && Matches(row, host, search, rules);

        UpdateFilterSummary();
    }

    private static bool Matches(PacketRowViewModel row, IPAddress? host, string search, IgnoreRules rules)
    {
        var packet = row.Packet;

        if (!rules.IsEmpty
            && (rules.IsProcessIgnored(packet.ProcessName) || rules.IsHostIgnored(row.RemoteHost)))
            return false;

        if (host is not null && !host.Equals(packet.SourceAddress) && !host.Equals(packet.DestinationAddress))
            return false;

        if (search.Length == 0) return true;

        return Contains(row.Source, search)
               || Contains(row.Destination, search)
               || Contains(packet.Protocol, search)
               || Contains(packet.Info, search)
               || Contains(packet.ProcessName, search);

        static bool Contains(string? haystack, string needle) =>
            haystack is not null && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateFilterSummary()
    {
        if (!IsFiltered && IgnoreListStore.Rules.IsEmpty)
        {
            FilterSummary = "";
            return;
        }

        int shown = System.Windows.Data.CollectionViewSource.GetDefaultView(Packets) is System.Windows.Data.ListCollectionView list
            ? list.Count
            : Packets.Count;
        FilterSummary = Loc.Format("Filter_ShowingOf", shown, Packets.Count);
        if (HasHidden) OnPropertyChanged(nameof(HiddenSummary));
    }

    // ---------------------------------------------------------------- hiding & host search

    /// <summary>Search over the hosts panel itself: domain, address or program.</summary>
    [ObservableProperty] private string _hostSearchText = "";

    partial void OnHostSearchTextChanged(string value) => ApplyHostFilter();

    public bool HasHidden => !IgnoreListStore.Rules.IsEmpty;
    /// <summary>"Hidden: powershell, github.com" - plus the shown count when no other filter chip
    /// is on screen to carry it.</summary>
    public string HiddenSummary => IsFiltered || FilterSummary.Length == 0
        ? Loc.Format("Ignore_Summary", IgnoreListStore.Rules.Describe())
        : Loc.Format("Ignore_Summary", IgnoreListStore.Rules.Describe()) + " · " + FilterSummary;

    public void HideHost(string? host) => IgnoreListStore.Rules.AddHost(host);

    public void HideProcess(string? process) => IgnoreListStore.Rules.AddProcess(process);

    [RelayCommand]
    private void ShowHidden() => IgnoreListStore.Rules.Clear();

    private void OnIgnoreRulesChanged(object? sender, EventArgs e)
    {
        // A hidden host can't stay the selected one - the grid would be filtered to nothing.
        if (SelectedHost is { } selected && IsHostHidden(selected)) SelectedHost = null;

        ApplyFilter();
        ApplyHostFilter();
        OnPropertyChanged(nameof(HasHidden));
        OnPropertyChanged(nameof(HiddenSummary));
    }

    private void ApplyHostFilter()
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Hosts);
        string search = HostSearchText.Trim();

        if (search.Length == 0 && IgnoreListStore.Rules.IsEmpty)
        {
            view.Filter = null;
            return;
        }

        // Live filtering: a host's program is usually attributed a few packets after the host
        // itself appears, and a host hidden by its program has to disappear when that happens.
        if (view is System.ComponentModel.ICollectionViewLiveShaping live && live.CanChangeLiveFiltering)
        {
            live.IsLiveFiltering = true;
            if (!live.LiveFilteringProperties.Contains(nameof(HostRowViewModel.ProcessText)))
            {
                live.LiveFilteringProperties.Add(nameof(HostRowViewModel.ProcessText));
                live.LiveFilteringProperties.Add(nameof(HostRowViewModel.Name));
            }
        }

        view.Filter = item => item is HostRowViewModel host
                              && !IsHostHidden(host)
                              && (search.Length == 0
                                  || host.Name.Contains(search, StringComparison.OrdinalIgnoreCase)
                                  || host.Address.Contains(search, StringComparison.OrdinalIgnoreCase)
                                  || host.ProcessText.Contains(search, StringComparison.OrdinalIgnoreCase)
                                  || host.Protocols.Contains(search, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Hidden by name or address, or because every program that used it is hidden.</summary>
    private static bool IsHostHidden(HostRowViewModel host)
    {
        var rules = IgnoreListStore.Rules;
        if (rules.IsEmpty) return false;

        return rules.IsHostIgnored(host.Name)
               || rules.IsHostIgnored(host.Address)
               || (host.ProcessNames.Count > 0 && host.ProcessNames.All(rules.IsProcessIgnored));
    }

    /// <summary>Bridges Core's platform-neutral resolver to the Windows socket tables.</summary>
    private static LocalProcess? ResolveLocalProcess(bool tcp, ushort localPort) =>
        ProcessPortMap.Shared.Lookup(tcp, localPort) is { } owner
            ? new LocalProcess(owner.Name, owner.ImagePath)
            : null;

    /// <summary>This machine's own addresses, so the tracker knows which end of a packet is remote.</summary>
    private static IEnumerable<IPAddress> LocalAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
                .Select(a => a.Address)
                .ToList();
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(PacketsCountText));
        OnPropertyChanged(nameof(BytesCountText));
        OnPropertyChanged(nameof(HostsCountText));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // LanguageChanged is static - not unsubscribing would keep this view model alive.
        LocalizationService.LanguageChanged -= OnLanguageChanged;
        IgnoreListStore.Rules.Changed -= OnIgnoreRulesChanged;
        _drainTimer.Stop();
        _session?.Dispose();
        _favicons.Dispose();

        // Order matters. The parser thread blocks on the semaphore, so cancelling alone can
        // leave it there; it is woken, then joined, and only then are the primitives disposed.
        // Disposing them first would throw ObjectDisposedException on a background thread -
        // which is an unhandled exception, i.e. the process dies on the way out.
        _parseCancellation.Cancel();
        try { _parseSignal.Release(); } catch (ObjectDisposedException) { }
        _parseThread?.Join(TimeSpan.FromSeconds(2));

        _parseCancellation.Dispose();
        _parseSignal.Dispose();
    }

    private volatile bool _disposed;
    private Thread? _parseThread;
}
