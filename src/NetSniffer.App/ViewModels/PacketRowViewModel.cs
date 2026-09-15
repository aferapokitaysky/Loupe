using CommunityToolkit.Mvvm.ComponentModel;
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

    public string Protocol => Packet.Protocol;
    public int Length => Packet.OriginalLength;
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
