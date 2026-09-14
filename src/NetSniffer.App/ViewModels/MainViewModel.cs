using System.Collections.Concurrent;
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
    private const int DrainBatchSize = 500;

    private readonly ConcurrentQueue<CapturedPacket> _incoming = new();
    private readonly DispatcherTimer _drainTimer;
    private readonly TcpStreamReassembler _reassembler = new();

    private CaptureSession? _session;
    private DateTimeOffset _captureStart;
    private bool _isInstallingNpcap;

    public ObservableCollection<CaptureDeviceInfo> Adapters { get; } = [];
    public ObservableCollection<PacketRowViewModel> Packets { get; } = [];

    [ObservableProperty] private CaptureDeviceInfo? _selectedAdapter;
    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private bool _isCapturing;
    [ObservableProperty] private bool _autoScroll = true;
    [ObservableProperty] private PacketRowViewModel? _selectedPacket;
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool _isCaptureEngineAvailable = true;

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

        _drainTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(150),
        };
        _drainTimer.Tick += (_, _) => DrainIncomingPackets();
        _drainTimer.Start();

        RefreshAdapters();
    }

    [RelayCommand]
    private void RefreshAdapters()
    {
        try
        {
            Adapters.Clear();
            foreach (var device in CaptureDeviceManager.ListDevices())
                Adapters.Add(device);

            IsCaptureEngineAvailable = true;
            SelectedAdapter ??= Adapters.FirstOrDefault();
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

    private bool CanInstallNpcap() => !_isInstallingNpcap;

    [RelayCommand(CanExecute = nameof(CanInstallNpcap))]
    private async Task InstallNpcapAsync()
    {
        _isInstallingNpcap = true;
        InstallNpcapCommand.NotifyCanExecuteChanged();

        var progress = new Progress<NpcapInstallStage>(stage => StatusMessage = stage switch
        {
            NpcapInstallStage.Downloading => Loc.Get("Pkt_Status_NpcapDownloading"),
            NpcapInstallStage.Launching => Loc.Get("Pkt_Status_NpcapLaunching"),
            _ => StatusMessage,
        });

        try
        {
            await NpcapInstaller.RunInstallerAsync(progress);
            RefreshAdapters();
            if (!IsCaptureEngineAvailable)
                StatusMessage = Loc.Get("Pkt_Status_NpcapInstallCancelled");
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Pkt_Status_NpcapInstallFailed", ex.Message);
        }
        finally
        {
            _isInstallingNpcap = false;
            InstallNpcapCommand.NotifyCanExecuteChanged();
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
        int drained = 0;
        while (drained < DrainBatchSize && _incoming.TryDequeue(out var captured))
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

    public void Dispose()
    {
        _drainTimer.Stop();
        _session?.Dispose();
    }
}
