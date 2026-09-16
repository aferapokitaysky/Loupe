using System.Runtime.InteropServices;
using Loupe.Core.Model;

namespace Loupe.Capture;

public sealed class PacketArrivedEventArgs(CapturedPacket packet) : EventArgs
{
    public CapturedPacket Packet { get; } = packet;
}

public sealed class CaptureStoppedEventArgs(string? errorReason) : EventArgs
{
    /// <summary>Null for a clean, user-requested stop; otherwise a message describing the capture failure.</summary>
    public string? ErrorReason { get; } = errorReason;
}

/// <summary>
/// One live capture on one adapter. Owns a background thread that blocks in
/// the native pcap_loop and raises <see cref="PacketArrived"/> for each frame.
/// Events fire ON THE CAPTURE THREAD - consumers (e.g. the WPF view model)
/// must marshal to their own thread before touching UI state.
/// </summary>
public sealed class CaptureSession : IDisposable
{
    private readonly CaptureDeviceInfo _device;
    private ulong _handle;
    private Thread? _captureThread;
    private long _packetCounter;

    // Kept as fields so the GC doesn't collect them while native code holds function pointers to them.
    private readonly PacketCallback _onPacket;
    private readonly CaptureStoppedCallback _onStopped;

    public event EventHandler<PacketArrivedEventArgs>? PacketArrived;
    public event EventHandler<CaptureStoppedEventArgs>? Stopped;

    public bool IsRunning { get; private set; }

    public CaptureSession(CaptureDeviceInfo device)
    {
        _device = device;
        _onPacket = HandlePacket;
        _onStopped = HandleStopped;
    }

    /// <param name="filterExpression">A BPF filter (tcpdump syntax), or null/empty for no filter.</param>
    public void Start(string? filterExpression = null, int snapLength = 65536, int readTimeoutMs = 100, bool promiscuous = true)
    {
        if (IsRunning) throw new InvalidOperationException("Capture already running.");

        _handle = NativeMethods.NsOpenDevice(_device.Name, snapLength, readTimeoutMs, promiscuous);
        if (_handle == 0)
            throw new CaptureException($"Could not open '{_device.Description}': {NativeMethods.GetLastError()}");

        if (!string.IsNullOrWhiteSpace(filterExpression))
        {
            int rc = NativeMethods.NsSetFilter(_handle, filterExpression);
            if (rc != 0)
            {
                string error = NativeMethods.GetLastError();
                NativeMethods.NsCloseDevice(_handle);
                _handle = 0;
                throw new CaptureException($"Invalid capture filter '{filterExpression}': {error}");
            }
        }

        _packetCounter = 0;
        IsRunning = true;
        _captureThread = new Thread(RunCaptureLoop) { IsBackground = true, Name = $"Loupe-Capture-{_device.Name}" };
        _captureThread.Start();
    }

    public void Stop()
    {
        if (!IsRunning || _handle == 0) return;
        NativeMethods.NsStopCapture(_handle);
    }

    private void RunCaptureLoop()
    {
        NativeMethods.NsRunCaptureLoop(_handle, _onPacket, _onStopped, IntPtr.Zero);
    }

    private void HandlePacket(IntPtr data, int length, int originalLength, long timestampUnixMicros, IntPtr _)
    {
        var bytes = new byte[length];
        if (length > 0) Marshal.Copy(data, bytes, 0, length);

        var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(timestampUnixMicros / 1000)
            .AddTicks((timestampUnixMicros % 1000) * 10);

        var packet = new CapturedPacket(Interlocked.Increment(ref _packetCounter), timestamp, bytes, originalLength);
        PacketArrived?.Invoke(this, new PacketArrivedEventArgs(packet));
    }

    private void HandleStopped(IntPtr reasonPtr, IntPtr _)
    {
        IsRunning = false;
        string? reason = Marshal.PtrToStringUTF8(reasonPtr);
        Stopped?.Invoke(this, new CaptureStoppedEventArgs(string.IsNullOrEmpty(reason) ? null : reason));
    }

    public void Dispose()
    {
        Stop();
        _captureThread?.Join(TimeSpan.FromSeconds(2));
        if (_handle != 0)
        {
            NativeMethods.NsCloseDevice(_handle);
            _handle = 0;
        }
    }
}
