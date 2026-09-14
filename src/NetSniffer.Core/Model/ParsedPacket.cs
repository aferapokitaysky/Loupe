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
}
