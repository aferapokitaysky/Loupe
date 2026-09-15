using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace NetSniffer.Capture.Processes;

/// <summary>A program that owns a socket.</summary>
/// <param name="ProcessId">The owning PID.</param>
/// <param name="Name">Executable name without extension ("chrome", "Telegram").</param>
/// <param name="ImagePath">Full path to the executable when Windows lets us read it, else null.</param>
public sealed record ProcessInfo(int ProcessId, string Name, string? ImagePath);

/// <summary>
/// Answers "which program owns this local port?" from the Windows TCP and UDP tables.
///
/// A packet capture sees addresses and ports, never processes; the kernel's connection tables
/// are the only place that link is kept. They are read in bulk and cached briefly - calling the
/// API per packet would cost more than dissecting the packet - and refreshed early on a miss,
/// because a brand-new connection shows up in its very first packets, before the next scheduled
/// refresh.
/// </summary>
public sealed class ProcessPortMap
{
    /// <summary>One table per process is plenty: the capture and the proxy share it, and so its cache.</summary>
    public static ProcessPortMap Shared { get; } = new();

    private static readonly TimeSpan RefreshInterval = TimeSpan.FromMilliseconds(1000);
    private static readonly TimeSpan MinRefreshOnMiss = TimeSpan.FromMilliseconds(150);

    private readonly object _refreshLock = new();
    private readonly ConcurrentDictionary<int, (ProcessInfo Info, long Seen)> _processes = new();
    private readonly Stopwatch _sinceRefresh = new();

    // Keyed by (protocol, local port). The local address is deliberately ignored: a socket bound
    // to 0.0.0.0 matches every interface, and two programs sharing a port number on different
    // addresses is rare enough that the simpler key is the better trade.
    private Dictionary<(bool Tcp, int Port), int> _owners = [];

    /// <summary>The program that owns a local TCP or UDP port, or null if nobody does (any more).</summary>
    public ProcessInfo? Lookup(bool tcp, int localPort)
    {
        if (localPort == 0) return null;

        EnsureFresh(RefreshInterval);
        if (TryOwner(tcp, localPort, out int pid)) return Describe(pid);

        // A miss is usually a connection younger than the table. Refresh early - but not on
        // every miss, or a flood of packets from an already-closed socket would hammer the API.
        EnsureFresh(MinRefreshOnMiss);
        return TryOwner(tcp, localPort, out pid) ? Describe(pid) : null;
    }

    /// <summary>
    /// The program on the other end of a loopback TCP connection - how the proxy finds out which
    /// app sent a request. <paramref name="clientEndPoint"/> is the remote end of the accepted
    /// socket, which is the client's own local endpoint.
    /// </summary>
    public ProcessInfo? LookupTcpClient(EndPoint? clientEndPoint) =>
        clientEndPoint is IPEndPoint ip ? Lookup(tcp: true, ip.Port) : null;

    private bool TryOwner(bool tcp, int port, out int pid)
    {
        var owners = Volatile.Read(ref _owners);
        return owners.TryGetValue((tcp, port), out pid);
    }

    private void EnsureFresh(TimeSpan maxAge)
    {
        if (_sinceRefresh.IsRunning && _sinceRefresh.Elapsed < maxAge) return;

        lock (_refreshLock)
        {
            if (_sinceRefresh.IsRunning && _sinceRefresh.Elapsed < maxAge) return;

            var owners = new Dictionary<(bool, int), int>();
            ReadTcpTable(AddressFamilyInet, owners);
            ReadTcpTable(AddressFamilyInet6, owners);
            ReadUdpTable(AddressFamilyInet, owners);
            ReadUdpTable(AddressFamilyInet6, owners);

            Volatile.Write(ref _owners, owners);
            _sinceRefresh.Restart();
        }
    }

    private ProcessInfo? Describe(int pid)
    {
        long now = Environment.TickCount64;
        if (_processes.TryGetValue(pid, out var cached) && now - cached.Seen < ProcessCacheMs)
            return cached.Info;

        var info = ResolveProcess(pid);

        // Misses are not cached (the process may be starting up), and hits expire, because
        // Windows reuses PIDs and a long capture would otherwise pin a dead program's name.
        if (info is not null) _processes[pid] = (info, now);
        return info;
    }

    private const long ProcessCacheMs = 30_000;

    private static ProcessInfo? ResolveProcess(int pid)
    {
        // PID 0 and 4 are the idle process and the kernel: real owners of real sockets, but
        // with no executable behind them.
        if (pid == 0) return new ProcessInfo(0, "System Idle", null);
        if (pid == 4) return new ProcessInfo(4, "System", null);

        try
        {
            using var process = Process.GetProcessById(pid);
            return new ProcessInfo(pid, process.ProcessName, QueryImagePath(pid));
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException)
        {
            return null; // exited between the table read and now
        }
    }

    /// <summary>
    /// Full image path via PROCESS_QUERY_LIMITED_INFORMATION, which - unlike Process.MainModule -
    /// works across bitness and for most processes of other users without elevation.
    /// </summary>
    private static string? QueryImagePath(int pid)
    {
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;

        try
        {
            var buffer = new char[1024];
            int size = buffer.Length;
            return QueryFullProcessImageNameW(handle, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    // ---------------------------------------------------------------- iphlpapi

    private const int AddressFamilyInet = 2;
    private const int AddressFamilyInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    // Row layouts (all DWORDs little-endian, ports big-endian in the low word):
    //   MIB_TCPROW_OWNER_PID   state, localAddr, localPort, remoteAddr, remotePort, pid   = 24 bytes
    //   MIB_TCP6ROW_OWNER_PID  localAddr[16], scope, localPort, remoteAddr[16], scope,
    //                          remotePort, state, pid                                    = 56 bytes
    //   MIB_UDPROW_OWNER_PID   localAddr, localPort, pid                                  = 12 bytes
    //   MIB_UDP6ROW_OWNER_PID  localAddr[16], scope, localPort, pid                       = 28 bytes
    private static void ReadTcpTable(int family, Dictionary<(bool, int), int> owners)
    {
        bool v6 = family == AddressFamilyInet6;
        ReadTable(
            (IntPtr buffer, ref int size) => GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0),
            rowSize: v6 ? 56 : 24,
            portOffset: v6 ? 20 : 8,
            pidOffset: v6 ? 52 : 20,
            tcp: true,
            owners);
    }

    private static void ReadUdpTable(int family, Dictionary<(bool, int), int> owners)
    {
        bool v6 = family == AddressFamilyInet6;
        ReadTable(
            (IntPtr buffer, ref int size) => GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0),
            rowSize: v6 ? 28 : 12,
            portOffset: v6 ? 20 : 4,
            pidOffset: v6 ? 24 : 8,
            tcp: false,
            owners);
    }

    private delegate uint TableReader(IntPtr buffer, ref int size);

    private static void ReadTable(
        TableReader read, int rowSize, int portOffset, int pidOffset, bool tcp,
        Dictionary<(bool, int), int> owners)
    {
        int size = 0;
        read(IntPtr.Zero, ref size);

        // The table can grow between the size query and the read; retry a couple of times.
        for (int attempt = 0; attempt < 3 && size > 0; attempt++)
        {
            size += 4096;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint result = read(buffer, ref size);
                if (result == ErrorInsufficientBuffer) continue;
                if (result != 0) return;

                int count = Marshal.ReadInt32(buffer);
                for (int i = 0; i < count; i++)
                {
                    IntPtr row = buffer + 4 + i * rowSize;
                    uint rawPort = (uint)Marshal.ReadInt32(row, portOffset);
                    int port = (int)(((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF));
                    int pid = Marshal.ReadInt32(row, pidOffset);

                    // Listening sockets and established ones can share a port; the first wins,
                    // and both belong to the same process in practice.
                    owners.TryAdd((tcp, port), pid);
                }

                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table, ref int size, bool sort, int addressFamily, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr table, ref int size, bool sort, int addressFamily, int tableClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, char[] buffer, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
