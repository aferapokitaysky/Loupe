using NetSniffer.Core.Model;
using NetSniffer.Core.Util;

namespace NetSniffer.App.ViewModels;

/// <summary>Thin, display-ready wrapper around a <see cref="ParsedPacket"/> for the packet-list grid.</summary>
public sealed class PacketRowViewModel
{
    public PacketRowViewModel(ParsedPacket packet, DateTimeOffset captureStart)
    {
        Packet = packet;
        RelativeTimeSeconds = (packet.Timestamp - captureStart).TotalSeconds;
    }

    public ParsedPacket Packet { get; }

    public long Number => Packet.Number;
    public double RelativeTimeSeconds { get; }
    public string Time => RelativeTimeSeconds.ToString("F6");
    public string Source => Packet.Source;
    public string Destination => Packet.Destination;
    public string Protocol => Packet.Protocol;
    public int Length => Packet.OriginalLength;
    public string Info => Packet.Info;

    /// <summary>Row accent color key, resolved against App.xaml resources - mirrors Wireshark's protocol coloring rules.</summary>
    public string ColorKey => Protocol switch
    {
        "TLS" => "ProtocolColorTls",
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
