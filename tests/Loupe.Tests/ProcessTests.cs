using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Loupe.Capture.Processes;

/// <summary>
/// Socket-to-process attribution against the real Windows connection tables. Loopback only, so
/// still hermetic: the sockets are opened by this test process, which therefore has to come
/// back as their owner.
/// </summary>
public static class ProcessTests
{
    public static async Task RunAsync()
    {
        T.Section("PROCESS ATTRIBUTION (OS socket tables, loopback)");

        int self = Environment.ProcessId;
        string selfName = Process.GetCurrentProcess().ProcessName;
        var map = new ProcessPortMap();

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int listenPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var client = new TcpClient();
        var accepting = listener.AcceptTcpClientAsync();
        await client.ConnectAsync(IPAddress.Loopback, listenPort);
        using var accepted = await accepting;

        int clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

        // Brand-new connection: this is the refresh-on-miss path, since the table was empty.
        var tcpOwner = map.Lookup(tcp: true, clientPort);
        T.Eq("fresh TCP connection attributed to its process", self, tcpOwner?.ProcessId ?? -1);
        T.Eq("process name resolved", selfName, tcpOwner?.Name ?? "");
        T.Check("image path resolved", tcpOwner?.ImagePath?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true,
            tcpOwner?.ImagePath ?? "(null)");

        // How the proxy uses it: the accepted socket's remote end is the client's local end.
        var viaAccept = map.LookupTcpClient(accepted.Client.RemoteEndPoint);
        T.Eq("proxy-side lookup finds the connecting program", self, viaAccept?.ProcessId ?? -1);

        T.Eq("listening port attributed too", self, map.Lookup(tcp: true, listenPort)?.ProcessId ?? -1);

        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;

        // Opened milliseconds after the lookups above, inside the refresh-on-miss throttle: the
        // very first packets of a connection can miss, and that is by design. The next packets,
        // a moment later, must not.
        await Task.Delay(200);
        T.Eq("UDP socket attributed (QUIC rides on these)", self, map.Lookup(tcp: false, udpPort)?.ProcessId ?? -1);

        T.Check("unused port has no owner", map.Lookup(tcp: true, FindFreePort()) is null);
        T.Check("port 0 is never looked up", map.Lookup(tcp: true, 0) is null);
    }

    private static int FindFreePort()
    {
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }
}
