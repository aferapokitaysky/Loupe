namespace Loupe.Core.Model;

/// <summary>
/// One protocol layer of a dissected packet (Ethernet, IPv4, TCP, TLS, ...),
/// mirroring the "protocol tree" pane in Wireshark-like tools.
/// </summary>
public sealed class PacketLayer
{
    public required string Name { get; init; }
    public required int Offset { get; init; }
    public required int Length { get; init; }
    public List<PacketField> Fields { get; } = [];

    public PacketLayer With(string name, string value, int offset, int length)
    {
        Fields.Add(new PacketField(name, value, offset, length));
        return this;
    }
}
