using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
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

    public ObservableCollection<CaptureDeviceInfo> Adapters { get; } = [];
    public ObservableCollection<PacketRowViewModel> Packets { get; } = [];

    [ObservableProperty] private CaptureDeviceInfo? _selectedAdapter;
    [ObservableProperty] private string _filterText = "";
    [ObservableProperty] private bool _isCapturing;
    [ObservableProperty] private bool _autoScroll = true;
    [ObservableProperty] private PacketRowViewModel? _selectedPacket;
    [ObservableProperty] private string _statusMessage = "Ready";
    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private long _totalBytes;

    public MainViewModel()
    {
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

            SelectedAdapter ??= Adapters.FirstOrDefault();
            StatusMessage = Adapters.Count == 0
                ? "No adapters found. Is Npcap installed?"
                : $"{Adapters.Count} adapter(s) found.";
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
            StatusMessage = "Capture engine unavailable: install the Npcap runtime from https://npcap.com/#download, then click Refresh.";
        }
        catch (BadImageFormatException)
        {
            StatusMessage = "Capture engine unavailable: NetSniffer.Native.dll is missing or was built for the wrong architecture (expected x64).";
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
            StatusMessage = e.ErrorReason is null ? "Capture stopped." : $"Capture stopped: {e.ErrorReason}";
            StartCaptureCommand.NotifyCanExecuteChanged();
            StopCaptureCommand.NotifyCanExecuteChanged();
        });

        try
        {
            _captureStart = DateTimeOffset.Now;
            _session.Start(string.IsNullOrWhiteSpace(FilterText) ? null : FilterText);
            IsCapturing = true;
            StatusMessage = $"Capturing on {SelectedAdapter.Description}…";
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
        StatusMessage = $"Saved {Packets.Count} packets to {dialog.FileName}";
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

        StatusMessage = $"Loaded {dialog.FileName}";
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
