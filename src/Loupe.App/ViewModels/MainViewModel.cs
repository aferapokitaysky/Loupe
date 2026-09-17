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
using Loupe.App.Localization;
using Loupe.Capture;
using Loupe.Capture.Processes;
using Loupe.Core.IO;
using Loupe.App.Services;
using Loupe.Core.Model;
using Loupe.Core.Naming;
using Loupe.Core.Parsing;
using Loupe.Core.Sessions;
using Loupe.Core.Tcp;

namespace Loupe.App.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    /// <summary>
    /// How many rows the grid keeps. Every row pins the packet's raw bytes, so this is really a
    /// memory setting: at ~1 KB a frame, 50k rows is around 50 MB. The old 250k quietly grew to
    /// a third of a gigabyte on a busy link. Adjustable in settings, within sane bounds.
    /// </summary>
    private static int MaxDisplayedPackets => Math.Clamp(AppSettings.Current.MaxPackets, 5_000, 500_000);

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
    [ObservableProperty] private bool _autoScroll = AppSettings.Current.AutoScroll;

    partial void OnAutoScrollChanged(bool value) => AppSettings.Update(s => s.AutoScroll = value);

    /// <summary>Fold runs of identical packets into one counted row. On by default: a bulk
    /// transfer is otherwise hundreds of lines that differ only in sequence number.</summary>
    [ObservableProperty] private bool _collapseRepeats = AppSettings.Current.CollapseRepeats;

    partial void OnCollapseRepeatsChanged(bool value) => AppSettings.Update(s => s.CollapseRepeats = value);

    /// <summary>Row highlighted in the hosts panel. Highlighting alone filters nothing - the
    /// tick boxes do that, so several hosts can be watched at once.</summary>
    [ObservableProperty] private HostRowViewModel? _selectedHost;

    /// <summary>Addresses of the ticked hosts. Empty means "everything".</summary>
    private readonly HashSet<IPAddress> _hostFilter = [];

    public int FilteredHostCount => _hostFilter.Count;

    /// <summary>Free-text search over endpoints, domains, protocol, program and summary.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFiltered))]
    private string _searchText = "";

    [ObservableProperty] private string _filterSummary = "";

    public bool IsFiltered => _hostFilter.Count > 0 || !string.IsNullOrWhiteSpace(SearchText);

    /// <summary>What the filter chip says: the single host by name, or how many are ticked.</summary>
    public string FilterScope => _hostFilter.Count switch
    {
        0 => "",
        1 => Hosts.FirstOrDefault(h => h.IsChecked)?.Name ?? "",
        var many => Loc.Format("Filter_HostCount", many),
    };
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
    [NotifyPropertyChangedFor(nameof(TotalBytesText))]
    private long _totalBytes;

    /// <summary>Volume for the top bar: short enough to sit under a label, e.g. "27.4 MB".</summary>
    public string TotalBytesText => TotalBytes switch
    {
        < 1024 => $"{TotalBytes} B",
        < 1024 * 1024 => $"{TotalBytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{TotalBytes / (1024.0 * 1024):F1} MB",
        _ => $"{TotalBytes / (1024.0 * 1024 * 1024):F2} GB",
    };

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
        ApplyHostSort();

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
            Name = "Loupe.Parse",
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
        else if (AppSettings.Current.StartCaptureOnLaunch && SelectedAdapter is not null)
            StartCapture();
    }

    [RelayCommand]
    private void RefreshAdapters()
    {
        try
        {
            // Clearing the collection makes the bound ComboBox null out SelectedAdapter, so
            // remember the user's pick by name and restore it instead of silently jumping
            // back to the default on every refresh.
            string? previouslySelected = SelectedAdapter?.Name ?? AppSettings.Current.LastAdapter;

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
            // Loupe.Native.dll (or the wpcap.dll it links against) isn't loadable -
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

    partial void OnSelectedAdapterChanged(CaptureDeviceInfo? value)
    {
        if (value is not null) AppSettings.Update(s => s.LastAdapter = value.Name);
        StartCaptureCommand.NotifyCanExecuteChanged();
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
            _captureStartKnown = false;
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

        // The hosts are about to disappear from the list; drop their filter with them rather than
        // leave the grid filtered on hosts nobody can see or untick any more.
        SelectedHost = null;
        ResetHostFilter();

        // The grid's predicate holds its own snapshot of the ticked hosts, so emptying the set is
        // not enough on its own - the filter has to be rebuilt from it.
        ApplyFilter();

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

    // ---------------------------------------------------------------- capture filter presets

    /// <summary>
    /// The filters worth having at hand. These are capture filters (BPF): the driver applies
    /// them before a packet is ever copied, which is what makes them worth using on a busy link.
    /// </summary>
    public IReadOnlyList<CaptureFilterPreset> FilterPresets { get; } =
    [
        new("Preset_All", ""),
        new("Preset_Web", "tcp port 80 or tcp port 443 or udp port 443"),
        new("Preset_Tls", "tcp port 443"),
        new("Preset_Quic", "udp port 443"),
        new("Preset_Http", "tcp port 80"),
        new("Preset_Dns", "port 53 or port 5353"),
        new("Preset_NoNoise", "not arp and not broadcast and not multicast"),
    ];

    /// <summary>
    /// Picking a preset fills the filter box. A capture filter is handed to the driver when the
    /// capture starts, so a running capture is restarted to apply it - the alternative is a
    /// filter that silently does nothing until someone happens to press stop and start.
    /// </summary>
    [ObservableProperty] private CaptureFilterPreset? _selectedFilterPreset = new("Preset_All", "");

    partial void OnSelectedFilterPresetChanged(CaptureFilterPreset? value)
    {
        if (value is null || FilterText == value.Expression) return;

        FilterText = value.Expression;

        if (!IsCapturing) return;

        StopCapture();
        StartCapture();
    }

    /// <summary>
    /// The reassembled conversation this packet belongs to, or null when it isn't TCP or the
    /// capture has since been cleared. The second value says which side of the stream the
    /// selected packet was sent from, so the view can show "what this end sent" first.
    /// </summary>
    public FollowStreamViewModel? FollowStream(PacketRowViewModel row)
    {
        if (row.Packet.Tcp is not { } tcp) return null;

        var key = new TcpStreamKey(tcp.SourceIp, tcp.SourcePort, tcp.DestinationIp, tcp.DestinationPort);
        return _reassembler.TryGetStream(key) is { } stream
            ? new FollowStreamViewModel(stream, key.IsAToB(tcp.SourceIp, tcp.SourcePort))
            : null;
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
        _captureStartKnown = false;
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

                // The time column counts from the first packet, not from when the button was
                // pressed: a file recorded yesterday would otherwise open with every row at a
                // large negative offset from "now".
                if (!_captureStartKnown)
                {
                    _captureStart = parsed.Timestamp;
                    _captureStartKnown = true;
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

    /// <summary>False until the first packet of this capture has set the time origin.</summary>
    private volatile bool _captureStartKnown;

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
            row.PropertyChanged += OnHostCheckedChanged;
            _hostRows[key] = row;
            Hosts.Add(row);
        }

        // Ordering is the view's job (see ApplyHostSort), not a hand-rolled Move loop: the user
        // can choose the key, and live sorting keeps it right as the numbers move.
        OnPropertyChanged(nameof(HostsCountText));
    }

    // ---------------------------------------------------------------- filtering

    private DispatcherTimer? _searchDebounce;

    /// <summary>Called when a host row is ticked or unticked in the panel.</summary>
    private void OnHostCheckedChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(HostRowViewModel.IsChecked) || sender is not HostRowViewModel row) return;

        if (row.IsChecked) _hostFilter.Add(row.AddressValue);
        else _hostFilter.Remove(row.AddressValue);

        ApplyFilter();
        OnPropertyChanged(nameof(IsFiltered));
        OnPropertyChanged(nameof(FilterScope));
        OnPropertyChanged(nameof(FilteredHostCount));
    }

    /// <summary>Ticks one host and unticks every other - "show me only this".</summary>
    public void ShowOnly(HostRowViewModel host)
    {
        foreach (var row in Hosts)
            row.IsChecked = ReferenceEquals(row, host);
    }

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
        foreach (var row in Hosts.Where(h => h.IsChecked).ToList())
            row.IsChecked = false;

        // Unticking only reaches hosts still in the list; the set is emptied outright so a host
        // that is gone can't keep the grid filtered from out of sight.
        ResetHostFilter();
        SearchText = "";
        _searchDebounce?.Stop();
        ApplyFilter();
    }

    private void ResetHostFilter()
    {
        if (_hostFilter.Count == 0) return;

        _hostFilter.Clear();
        OnPropertyChanged(nameof(IsFiltered));
        OnPropertyChanged(nameof(FilterScope));
        OnPropertyChanged(nameof(FilteredHostCount));
    }

    /// <summary>
    /// Filters the grid's view rather than the collection: the capture itself (counters, saved
    /// .pcap, the folding of repeats) keeps seeing every packet, only what is shown narrows.
    /// </summary>
    private void ApplyFilter()
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Packets);
        string search = SearchText.Trim();
        var rules = IgnoreListStore.Rules;

        // Snapshot the ticked hosts: the predicate runs for every row, and must not race with
        // the panel being ticked while a refresh is in flight.
        var hosts = _hostFilter.Count == 0 ? null : _hostFilter.ToHashSet();

        view.Filter = hosts is null && search.Length == 0 && rules.IsEmpty
            ? null // no predicate at all: nothing to evaluate per row
            : item => item is PacketRowViewModel row && Matches(row, hosts, search, rules);

        UpdateFilterSummary();
    }

    private static bool Matches(PacketRowViewModel row, HashSet<IPAddress>? hosts, string search, IgnoreRules rules)
    {
        var packet = row.Packet;

        if (!rules.IsEmpty
            && (rules.IsProcessIgnored(packet.ProcessName) || rules.IsHostIgnored(row.RemoteHost)))
            return false;

        // Any of the ticked hosts, at either end.
        if (hosts is not null
            && !(packet.SourceAddress is { } source && hosts.Contains(source))
            && !(packet.DestinationAddress is { } destination && hosts.Contains(destination)))
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

    /// <summary>How the hosts panel is ordered. Volume first by default - the loudest host is
    /// usually the question - but "most recent" and "by name" are what you want once you know
    /// which host you are looking for.</summary>
    public IReadOnlyList<SortOption> HostSortOptions { get; } =
    [
        new("Bytes", "Sort_Bytes"),
        new("Packets", "Sort_Packets"),
        new("Recent", "Sort_Recent"),
        new("Name", "Sort_Name"),
    ];

    [ObservableProperty] private SortOption _hostSort = new("Bytes", "Sort_Bytes");

    partial void OnHostSortChanged(SortOption value) => ApplyHostSort();

    private void ApplyHostSort()
    {
        if (System.Windows.Data.CollectionViewSource.GetDefaultView(Hosts) is not System.Windows.Data.ListCollectionView view)
            return;

        view.CustomSort = HostSort.Key switch
        {
            "Packets" => Comparer<object>.Create((a, b) => Compare(b, a, h => h.Packets)),
            "Recent" => Comparer<object>.Create((a, b) => Compare(b, a, h => h.LastSeen)),
            "Name" => Comparer<object>.Create((a, b) =>
                string.Compare(((HostRowViewModel)a).Name, ((HostRowViewModel)b).Name, StringComparison.OrdinalIgnoreCase)),
            _ => Comparer<object>.Create((a, b) => Compare(b, a, h => h.Bytes)),
        };

        // Live sorting, so a host climbing the list moves as its traffic grows rather than only
        // when something else forces a refresh.
        view.IsLiveSorting = true;
        foreach (string property in new[] { nameof(HostRowViewModel.Bytes), nameof(HostRowViewModel.Packets), nameof(HostRowViewModel.LastSeen), nameof(HostRowViewModel.Name) })
        {
            if (!view.LiveSortingProperties.Contains(property)) view.LiveSortingProperties.Add(property);
        }

        static int Compare<TKey>(object a, object b, Func<HostRowViewModel, TKey> key) where TKey : IComparable<TKey> =>
            key((HostRowViewModel)a).CompareTo(key((HostRowViewModel)b));
    }

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
        // A host that just became hidden must not keep filtering the grid from out of sight.
        foreach (var row in Hosts.Where(h => h.IsChecked && IsHostHidden(h)).ToList())
            row.IsChecked = false;

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
