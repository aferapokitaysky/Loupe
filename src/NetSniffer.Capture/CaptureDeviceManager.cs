using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NetSniffer.Capture;

public static class CaptureDeviceManager
{
    /// <summary>Enumerates capture-capable adapters. Requires the Npcap runtime to be installed.</summary>
    public static IReadOnlyList<CaptureDeviceInfo> ListDevices()
    {
        int count = NativeMethods.NsListDevices(null, 0);
        if (count < 0)
            throw new CaptureException($"Failed to enumerate adapters: {NativeMethods.GetLastError()}");
        if (count == 0)
            return [];

        var buffer = new NativeDeviceInfo[count];
        int actual = NativeMethods.NsListDevices(buffer, count);
        if (actual < 0)
            throw new CaptureException($"Failed to enumerate adapters: {NativeMethods.GetLastError()}");

        var interfaces = SafeGetInterfaces();
        var internetNic = FindInternetInterface();

        var result = new List<CaptureDeviceInfo>(Math.Min(actual, count));
        for (int i = 0; i < Math.Min(actual, count); i++)
        {
            string name = Marshal.PtrToStringUTF8(buffer[i].Name) ?? "";
            string description = Marshal.PtrToStringUTF8(buffer[i].Description) ?? name;

            // pcap names devices "\Device\NPF_{GUID}" and NetworkInterface.Id is that same
            // GUID, so devices and Windows interfaces line up exactly - no name guessing.
            var nic = interfaces.FirstOrDefault(n => name.Contains(n.Id, StringComparison.OrdinalIgnoreCase));

            result.Add(new CaptureDeviceInfo(name, description)
            {
                Kind = ClassifyAdapter(nic, description),
                IsInternet = nic is not null && internetNic is not null &&
                             string.Equals(nic.Id, internetNic.Id, StringComparison.OrdinalIgnoreCase),
            });
        }

        // Put the adapter carrying internet traffic first, then real NICs, then the
        // WAN-miniport/virtual clutter that pcap would otherwise list at the top.
        return [.. result
            .OrderByDescending(d => d.IsInternet)
            .ThenBy(d => d.Kind switch
            {
                AdapterKind.Ethernet or AdapterKind.WiFi => 0,
                AdapterKind.Bluetooth => 1,
                AdapterKind.Virtual => 2,
                AdapterKind.Loopback => 3,
                _ => 4,
            })
            .ThenBy(d => d.Description, StringComparer.CurrentCulture)];
    }

    private static AdapterKind ClassifyAdapter(NetworkInterface? nic, string description)
    {
        // The reported NetworkInterfaceType lies often enough that the name has to break ties:
        // Bluetooth PAN claims to be Ethernet, and Wi-Fi Direct/Hyper-V adapters claim to be
        // real Wi-Fi and Ethernet. Check the telltale names first.
        string text = nic?.Description ?? description;

        if (Mentions(text, "bluetooth")) return AdapterKind.Bluetooth;
        if (Mentions(text, "loopback")) return AdapterKind.Loopback;
        if (nic is null) return AdapterKind.Other;
        if (Mentions(text, "virtual", "hyper-v", "vethernet", "wi-fi direct", "vmware", "virtualbox", "tap-windows"))
            return AdapterKind.Virtual;

        return nic.NetworkInterfaceType switch
        {
            NetworkInterfaceType.Wireless80211 => AdapterKind.WiFi,
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or
            NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx => AdapterKind.Ethernet,
            NetworkInterfaceType.Loopback => AdapterKind.Loopback,
            NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp => AdapterKind.Virtual,
            _ => AdapterKind.Other,
        };
    }

    private static bool Mentions(string text, params string[] needles) =>
        needles.Any(n => text.Contains(n, StringComparison.OrdinalIgnoreCase));

    private static List<NetworkInterface> SafeGetInterfaces()
    {
        try { return [.. NetworkInterface.GetAllNetworkInterfaces()]; }
        catch { return []; }
    }

    public static string NativeLibraryVersion => NativeMethods.GetLibVersion();

    /// <summary>
    /// Picks the adapter a capture should start on. pcap lists devices in driver order, which
    /// on Windows puts WAN miniports first - they carry no traffic, so defaulting to the first
    /// entry makes a working capture look broken. Prefer an interface that is up, not loopback
    /// or a tunnel, has a default gateway, and has actually seen the most bytes.
    /// </summary>
    public static CaptureDeviceInfo? PickDefault(IEnumerable<CaptureDeviceInfo> devices)
    {
        var candidates = devices.ToList();
        return candidates.FirstOrDefault(d => d.IsInternet)
               ?? candidates.FirstOrDefault(d => d.Kind is AdapterKind.Ethernet or AdapterKind.WiFi)
               ?? candidates.FirstOrDefault();
    }

    /// <summary>
    /// Resolves the NIC carrying internet traffic by asking the OS routing table which local
    /// address it would use for a public destination. Connecting a UDP socket sends nothing
    /// on the wire - it only binds the local endpoint the route would pick.
    /// </summary>
    private static NetworkInterface? FindInternetInterface()
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect(new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53));
            if (probe.LocalEndPoint is not IPEndPoint { Address: var localAddress }) return null;

            return NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(nic =>
                nic.OperationalStatus == OperationalStatus.Up &&
                nic.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(localAddress)));
        }
        catch
        {
            return null;
        }
    }
}

public sealed class CaptureException(string message) : Exception(message);
