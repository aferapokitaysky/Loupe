namespace Loupe.Core.Tcp;

/// <summary>
/// Canonical, direction-independent identifier for a TCP connection: both
/// packet directions of the same connection hash to the same key.
/// </summary>
public readonly record struct TcpStreamKey
{
    public string EndpointA { get; }
    public ushort PortA { get; }
    public string EndpointB { get; }
    public ushort PortB { get; }

    public TcpStreamKey(string ipX, ushort portX, string ipY, ushort portY)
    {
        // Order endpoints deterministically so (A,B) and (B,A) collapse to one key.
        if (string.CompareOrdinal(ipX, ipY) < 0 || (ipX == ipY && portX <= portY))
        {
            EndpointA = ipX; PortA = portX; EndpointB = ipY; PortB = portY;
        }
        else
        {
            EndpointA = ipY; PortA = portY; EndpointB = ipX; PortB = portX;
        }
    }

    /// <summary>True if (srcIp, srcPort) matches the "A" side of this key.</summary>
    public bool IsAToB(string srcIp, ushort srcPort) => srcIp == EndpointA && srcPort == PortA;

    public override string ToString() => $"{EndpointA}:{PortA} ↔ {EndpointB}:{PortB}";
}
