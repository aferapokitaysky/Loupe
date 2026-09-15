using System.Collections.Concurrent;
using System.Diagnostics;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NetSniffer.App.Localization;
using NetSniffer.Capture;
using NetSniffer.Core.IO;
using NetSniffer.Core.Model;
using NetSniffer.Core.Parsing;
using NetSniffer.Core.Tcp;

namespace NetSniffer.App.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private const int MaxDisplayedPackets = 250_000;
    private const int DrainBudgetMs = 25;

    private readonly ConcurrentQueue<CapturedPacket> _incoming = new();
    private readonly DispatcherTimer _drainTimer;
    private readonly TcpStreamReassembler _reassembler = new();

    private CaptureSession? _session;
    private DateTimeOffset _captureStart;

    public ObservableCollection<CaptureDeviceInfo> Adapters { get; } = [];
    public ObservableCollection<PacketRowViewModel> Packets { get; } = [];

    [ObservableProperty] private CaptureDeviceInfo? _selectedAdapter;
    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private bool _isCapturing;
    [ObservableProperty] private bool _autoScroll = true;
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

    public string PacketsCountText => Loc.Format("Pkt_StatusBar_Packets", TotalPackets);
    public string BytesCountText => Loc.Format("Pkt_StatusBar_Bytes", TotalBytes);

    public MainViewModel()
    {
        StatusMessage = Loc.Get("Pkt_Status_Ready");

        // The status-bar counters bake their label into the string, so they'd keep the old
        // language until the next packet arrived. Re-read them when the language changes.
        LocalizationService.LanguageChanged += OnLanguageChanged;

        _drainTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(150),
        };
        _drainTimer.Tick += (_, _) => DrainIncomingPackets();
        _drainTimer.Start();

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
        _session.PacketArrived += (_, e) => _incoming.Enqueue(e.Packet);
        _session.Stopped += (_, e) => Application.Current.Dispatcher.BeginInvoke(() =>
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
        Packets.Clear();
        _reassembler.Clear();
        TotalPackets = 0;
        TotalBytes = 0;
        SelectedPacket = null;
    }

    [RelayCommand]
    private void SaveCapture()
    {
        var dialog = new SaveFileDialog { Filter = "pcap files (*.pcap)|*.pcap", FileName = "capture.pcap" };
        if (dialog.ShowDialog() != true) return;

        PcapFile.Write(dialog.FileName, Packets.Select(p => new CapturedPacket(
            p.Packet.Number, p.Packet.Timestamp, p.Packet.RawData, p.Packet.OriginalLength)));
        StatusMessage = Loc.Format("Pkt_Status_Saved", Packets.Count, dialog.FileName);
    }

    [RelayCommand]
    private void OpenCapture()
    {
        var dialog = new OpenFileDialog { Filter = "pcap files (*.pcap)|*.pcap" };
        if (dialog.ShowDialog() != true) return;

        ClearPackets();
        _captureStart = DateTimeOffset.Now;
        foreach (var captured in PcapFile.Read(dialog.FileName))
            _incoming.Enqueue(captured);

        StatusMessage = Loc.Format("Pkt_Status_Loaded", dialog.FileName);
    }

    private void DrainIncomingPackets()
    {
        // Bounded by time, not by a fixed count: a live adapter trickles packets in and stays
        // well under the budget, while opening a large .pcap (which dumps the whole file into
        // the queue at once) still fills the grid in a few ticks instead of minutes.
        var budget = Stopwatch.StartNew();
        int drained = 0;

        while (budget.ElapsedMilliseconds < DrainBudgetMs && _incoming.TryDequeue(out var captured))
        {
            var parsed = PacketParser.Parse(captured);
            _reassembler.Ingest(parsed);

            Packets.Add(new PacketRowViewModel(parsed, _captureStart));
            TotalPackets++;
            TotalBytes += parsed.OriginalLength;
            drained++;
        }

        if (drained == 0) return;

        while (Packets.Count > MaxDisplayedPackets)
            Packets.RemoveAt(0);
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(PacketsCountText));
        OnPropertyChanged(nameof(BytesCountText));
    }

    public void Dispose()
    {
        // LanguageChanged is static - not unsubscribing would keep this view model alive.
        LocalizationService.LanguageChanged -= OnLanguageChanged;
        _drainTimer.Stop();
        _session?.Dispose();
    }
}
