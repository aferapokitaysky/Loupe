using CommunityToolkit.Mvvm.ComponentModel;
using NetSniffer.App.Services;
using NetSniffer.Core.Model;
using NetSniffer.Core.Naming;
using NetSniffer.Core.Util;

namespace NetSniffer.App.ViewModels;

/// <summary>Thin, display-ready wrapper around a <see cref="ParsedPacket"/> for the packet-list grid.</summary>
public sealed partial class PacketRowViewModel : ObservableObject
{
    private readonly HostNameRegistry? _names;

    public PacketRowViewModel(ParsedPacket packet, DateTimeOffset captureStart, HostNameRegistry? names = null)
    {
        Packet = packet;
        _names = names;
        RelativeTimeSeconds = (packet.Timestamp - captureStart).TotalSeconds;
        _totalLength = packet.OriginalLength;
    }

    public ParsedPacket Packet { get; }

    public long Number => Packet.Number;
    public double RelativeTimeSeconds { get; }
    public string Time => RelativeTimeSeconds.ToString("F6");

    /// <summary>
    /// The domain when the capture has seen a name for the address, else the raw address.
    /// Not cached: the name for an address usually arrives a few packets after the first ones
    /// to it (an SNI follows the handshake), and rows already on screen should pick it up.
    /// </summary>
    public string Source => Describe(Packet.SourceAddress, Packet.SourcePort, Packet.Source);

    public string Destination => Describe(Packet.DestinationAddress, Packet.DestinationPort, Packet.Destination);

    /// <summary>The literal addresses, always - shown in the detail pane so the IP is never lost.</summary>
    public string SourceAddressText => Packet.Source;
    public string DestinationAddressText => Packet.Destination;

    private string Describe(System.Net.IPAddress? address, ushort port, string fallback)
    {
        if (_names is null || address is null) return fallback;
        return _names.TryGetName(address, out var name) ? (port == 0 ? name : $"{name}:{port}") : fallback;
    }

    /// <summary>Called when new names are learned so visible rows can relabel themselves.</summary>
    public void RefreshNames()
    {
        OnPropertyChanged(nameof(Source));
        OnPropertyChanged(nameof(Destination));
    }

    /// <summary>How many packets this row stands for. 1 unless a run was folded into it.</summary>
    [ObservableProperty] private int _repeatCount = 1;

    public bool IsRepeated => RepeatCount > 1;
    public string RepeatText => RepeatCount > 1 ? $"×{RepeatCount}" : "";

    /// <summary>Total bytes across the folded run, so a collapsed row still reports real volume.</summary>
    [ObservableProperty] private int _totalLength;

    /// <summary>
    /// Folds <paramref name="next"/> into this row when it is another packet of the same shape -
    /// same endpoints, protocol and summary. Bulk transfers are otherwise hundreds of rows that
    /// differ only in sequence number, which is exactly what makes a busy capture unreadable.
    /// </summary>
    public bool TryCollapse(PacketRowViewModel next)
    {
        if (!SameShapeAs(next)) return false;

        // Collapsing is a display decision, never a data one: the folded packets are kept so a
        // saved .pcap still contains every frame that was on the wire.
        (_folded ??= []).Add(next.Packet);

        RepeatCount++;
        TotalLength += next.Packet.OriginalLength;
        OnPropertyChanged(nameof(IsRepeated));
        OnPropertyChanged(nameof(RepeatText));
        OnPropertyChanged(nameof(Length));
        return true;
    }

    private List<ParsedPacket>? _folded;

    /// <summary>Every packet this row stands for, in capture order.</summary>
    public IEnumerable<ParsedPacket> AllPackets
    {
        get
        {
            yield return Packet;
            if (_folded is null) yield break;
            foreach (var packet in _folded) yield return packet;
        }
    }

    private bool SameShapeAs(PacketRowViewModel other) =>
        Packet.Protocol == other.Packet.Protocol
        && Packet.SourcePort == other.Packet.SourcePort
        && Packet.DestinationPort == other.Packet.DestinationPort
        && Equals(Packet.SourceAddress, other.Packet.SourceAddress)
        && Equals(Packet.DestinationAddress, other.Packet.DestinationAddress)
        // Info carries sequence numbers, which differ every packet; compare the part before
        // them so a run of ordinary data segments still folds, while a SYN or a DNS query -
        // whose wording differs - never folds into its neighbour.
        && SummaryShape(Packet.Info) == SummaryShape(other.Packet.Info);

    private static string SummaryShape(string info)
    {
        int seq = info.IndexOf(" Seq=", StringComparison.Ordinal);
        if (seq >= 0) return info[..seq];

        int len = info.IndexOf(" Len=", StringComparison.Ordinal);
        return len >= 0 ? info[..len] : info;
    }

    /// <summary>The local program behind this packet, or empty when it couldn't be attributed.</summary>
    public string Process => Packet.ProcessName ?? "";

    /// <summary>Loaded on first display, on the UI thread (see <see cref="AppIconService"/>).</summary>
    public System.Windows.Media.ImageSource? ProcessIcon => AppIconService.Get(Packet.ProcessImagePath);

    public string Protocol => Packet.Protocol;
    /// <summary>Bytes on the wire - for a collapsed row, the whole run rather than one packet.</summary>
    public int Length => TotalLength;
    public string Info => Packet.Info;

    /// <summary>Row accent color key, resolved against App.xaml resources - mirrors Wireshark's protocol coloring rules.</summary>
    public string ColorKey => Protocol switch
    {
        "TLS" => "ProtocolColorTls",
        "QUIC" => "ProtocolColorQuic",
        "HTTP" => "ProtocolColorHttp",
        "DNS" => "ProtocolColorDns",
        "TCP" => "ProtocolColorTcp",
        "UDP" => "ProtocolColorUdp",
        "ARP" => "ProtocolColorArp",
        "ICMP" or "ICMPv6" => "ProtocolColorIcmp",
        _ => "ProtocolColorDefault",
    };

    public string HexDump => Core.Util.HexDump.Format(Packet.RawData);
}
