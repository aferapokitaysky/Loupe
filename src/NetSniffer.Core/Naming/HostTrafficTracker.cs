using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using NetSniffer.Core.Model;

namespace NetSniffer.Core.Naming;

/// <summary>A remote endpoint the capture has talked to, with its running totals.</summary>
public sealed class HostTraffic
{
    public required IPAddress Address { get; init; }

    /// <summary>The domain when one has been observed, else the address as text.</summary>
    public string Name { get; set; } = "";

    public bool HasName { get; set; }

    public long Packets;
    public long Bytes;
    public long SentBytes;
    public long ReceivedBytes;

    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Protocols seen on this endpoint ("TLS", "DNS", "QUIC", ...), most useful first.</summary>
    public HashSet<string> Protocols { get; } = [];

    /// <summary>Remote ports contacted - 443, 80, 53 and friends.</summary>
    public HashSet<ushort> Ports { get; } = [];

    /// <summary>Local programs that talked to this host, by name, with their executable path
    /// when known (null otherwise). Usually one; a CDN address serves several.</summary>
    public Dictionary<string, string?> Processes { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>A local program resolved for a socket: its name and, when readable, its executable.</summary>
public readonly record struct LocalProcess(string Name, string? ImagePath);

/// <summary>Resolves the local program owning a TCP (<c>tcp</c> true) or UDP port, or null.</summary>
public delegate LocalProcess? LocalProcessResolver(bool tcp, ushort localPort);

/// <summary>
/// Rolls packets up per remote host, which is what makes a fast link readable: a gigabit of
/// QUIC is thousands of unreadable grid rows but only a handful of hosts.
/// </summary>
public sealed class HostTrafficTracker
{
    private readonly ConcurrentDictionary<IPAddress, HostTraffic> _hosts = new();
    private readonly HashSet<IPAddress> _localAddresses;
    private readonly LocalProcessResolver? _resolveProcess;

    /// <param name="localAddresses">This machine's own addresses, used to decide which end of
    /// a packet is the remote one. May be empty, in which case the public address wins and a
    /// LAN-only conversation falls back to the destination.</param>
    /// <param name="resolveProcess">Optional: maps a local port to the program that owns it.
    /// Core stays platform-neutral; the capture layer supplies the Windows implementation.</param>
    public HostTrafficTracker(IEnumerable<IPAddress>? localAddresses = null, LocalProcessResolver? resolveProcess = null)
    {
        _localAddresses = localAddresses is null ? [] : [.. localAddresses];
        _resolveProcess = resolveProcess;
    }

    public int Count => _hosts.Count;

    public void Ingest(ParsedPacket packet, HostNameRegistry names)
    {
        var (remote, remotePort, outbound) = PickRemote(packet);
        if (remote is null || IsUninteresting(remote)) return;

        // Our end of the conversation is whichever port isn't the remote one. Only TCP and UDP
        // have sockets to attribute; ICMP and friends belong to no program.
        LocalProcess? process = null;
        if (_resolveProcess is not null && packet.Protocol is not ("ICMP" or "ICMPv6" or "ARP"))
        {
            ushort localPort = outbound ? packet.SourcePort : packet.DestinationPort;
            bool tcp = packet.Tcp is not null;
            if (localPort != 0) process = _resolveProcess(tcp, localPort);
        }

        if (process is { } owner)
        {
            packet.ProcessName = owner.Name;
            packet.ProcessImagePath = owner.ImagePath;
        }

        var host = _hosts.GetOrAdd(remote, address => new HostTraffic
        {
            Address = address,
            Name = address.ToString(),
            FirstSeen = packet.Timestamp,
        });

        lock (host)
        {
            host.Packets++;
            host.Bytes += packet.OriginalLength;
            if (outbound) host.SentBytes += packet.OriginalLength;
            else host.ReceivedBytes += packet.OriginalLength;

            host.LastSeen = packet.Timestamp;
            if (!string.IsNullOrEmpty(packet.Protocol)) host.Protocols.Add(packet.Protocol);
            if (remotePort != 0) host.Ports.Add(remotePort);

            // Keep the first path seen for a name; a later lookup that couldn't read the image
            // (the process was exiting) mustn't wipe out a good one.
            if (process is { } p && (!host.Processes.TryGetValue(p.Name, out var knownPath) || knownPath is null))
                host.Processes[p.Name] = p.ImagePath;

            // The name usually shows up after the first packets to an address (the DNS answer
            // precedes the connection, but an SNI does not), so re-check it every time until found.
            if (!host.HasName && names.TryGetName(remote, out var name))
            {
                host.Name = name;
                host.HasName = true;
            }
        }
    }

    public List<HostTraffic> Snapshot() => [.. _hosts.Values];

    public void Clear() => _hosts.Clear();

    /// <summary>Works out which end of the packet is the far end, and whether we sent it.</summary>
    private (IPAddress? Remote, ushort Port, bool Outbound) PickRemote(ParsedPacket packet)
    {
        var source = packet.SourceAddress;
        var destination = packet.DestinationAddress;
        if (source is null || destination is null) return (null, 0, false);

        if (_localAddresses.Count > 0)
        {
            if (_localAddresses.Contains(source)) return (destination, packet.DestinationPort, true);
            if (_localAddresses.Contains(destination)) return (source, packet.SourcePort, false);
        }

        // No local-address list (or neither end matched - a capture opened from a .pcap taken
        // elsewhere): the routable address is the interesting one.
        bool sourcePrivate = IsPrivate(source);
        bool destinationPrivate = IsPrivate(destination);
        if (sourcePrivate && !destinationPrivate) return (destination, packet.DestinationPort, true);
        if (!sourcePrivate && destinationPrivate) return (source, packet.SourcePort, false);

        return (destination, packet.DestinationPort, true);
    }

    /// <summary>Broadcast/multicast noise would otherwise flood the host list.</summary>
    private static bool IsUninteresting(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return true;

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6Multicast || address.IsIPv6LinkLocal;

        byte[] octets = address.GetAddressBytes();
        return octets[0] >= 224                                   // multicast + reserved
               || octets is [255, 255, 255, 255]                  // broadcast
               || octets is [169, 254, ..];                       // link-local / APIPA
    }

    private static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || IPAddress.IsLoopback(address);

        byte[] o = address.GetAddressBytes();
        return o switch
        {
            [10, ..] => true,
            [192, 168, ..] => true,
            [172, >= 16 and <= 31, ..] => true,
            [127, ..] => true,
            [169, 254, ..] => true,
            _ => false,
        };
    }
}
