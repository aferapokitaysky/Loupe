namespace Loupe.Core.Model;

/// <summary>Typed TCP header fields needed for stream reassembly, alongside the human-readable layer tree.</summary>
public sealed record TcpInfo(
    string SourceIp,
    ushort SourcePort,
    string DestinationIp,
    ushort DestinationPort,
    uint SequenceNumber,
    byte Flags,
    int PayloadOffset,
    int PayloadLength)
{
    public bool IsSyn => (Flags & 0x02) != 0;
    public bool IsFin => (Flags & 0x01) != 0;
    public bool IsRst => (Flags & 0x04) != 0;
}
