using System.Net;

namespace NetSniffer.Core.Model;

/// <summary>
/// A fully dissected packet: the raw bytes, the layer tree, and the summary
/// fields shown in the packet-list grid (Wireshark's "No./Time/Source/..." row).
/// </summary>
public sealed class ParsedPacket
{
    public required long Number { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required byte[] RawData { get; init; }
    public required int OriginalLength { get; init; }

    public List<PacketLayer> Layers { get; } = [];

    public string Source { get; set; } = "";
    public string Destination { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string Info { get; set; } = "";

    /// <summary>Typed TCP header fields when this is a TCP segment, else null.</summary>
    public TcpInfo? Tcp { get; set; }

    /// <summary>Network-layer addresses, kept typed alongside the display strings so callers
    /// don't have to parse "1.2.3.4:443" back apart. Null for non-IP frames (ARP, bare Ethernet).</summary>
    public IPAddress? SourceAddress { get; set; }
    public IPAddress? DestinationAddress { get; set; }

    /// <summary>Transport ports, 0 when the packet has no transport layer with ports.</summary>
    public ushort SourcePort { get; set; }
    public ushort DestinationPort { get; set; }

    /// <summary>
    /// The local program that sent or received this packet, when it could be attributed from the
    /// OS socket tables. Null for packets that belong to no local socket (someone else's traffic
    /// seen in promiscuous mode, broadcasts) or whose socket was already gone.
    /// </summary>
    public string? ProcessName { get; set; }

    /// <summary>Full path of <see cref="ProcessName"/>'s executable, for its icon. Often null.</summary>
    public string? ProcessImagePath { get; set; }

    /// <summary>Names this packet revealed (DNS answers, TLS SNI, HTTP Host). Usually empty.</summary>
    public List<HostNameHint>? NameHints { get; set; }

    public void AddNameHint(IPAddress? address, string name, NameHintSource source)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        (NameHints ??= []).Add(new HostNameHint(address, name, source));
    }
}
