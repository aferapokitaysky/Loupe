using System.Collections.Concurrent;
using System.Net;
using Loupe.Core.Model;

namespace Loupe.Core.Naming;

/// <summary>
/// Remembers which domain each address belongs to, learned passively from the traffic:
/// A/AAAA answers in DNS responses, TLS SNI, and plaintext HTTP Host headers.
///
/// Passive on purpose - no reverse lookups are issued. A PTR record usually names the
/// hosting provider ("ec2-3-5-8-1.compute.amazonaws.com"), not the site the user visited,
/// and firing lookups for every address in a capture would generate its own traffic and
/// leak the capture contents to a resolver.
/// </summary>
public sealed class HostNameRegistry
{
    /// <summary>A DNS answer beats an SNI, which beats a Host header: the first is the actual
    /// mapping, the others are what the client believed it was connecting to.</summary>
    private static int Rank(NameHintSource source) => source switch
    {
        NameHintSource.DnsAnswer => 3,
        NameHintSource.TlsSni => 2,
        _ => 1,
    };

    private readonly ConcurrentDictionary<IPAddress, Entry> _names = new();

    private sealed record Entry(string Name, int Rank);

    public int Count => _names.Count;

    public void Ingest(ParsedPacket packet)
    {
        if (packet.NameHints is not { Count: > 0 } hints) return;

        foreach (var hint in hints)
        {
            var address = hint.Address;
            if (address is null || string.IsNullOrWhiteSpace(hint.Name)) continue;

            var candidate = new Entry(hint.Name.TrimEnd('.'), Rank(hint.Source));
            _names.AddOrUpdate(
                address,
                candidate,
                // A CDN address serves many names; keep the first of equal rank rather than
                // letting the label flap between them on every packet.
                (_, existing) => candidate.Rank > existing.Rank ? candidate : existing);
        }
    }

    public bool TryGetName(IPAddress? address, out string name)
    {
        if (address is not null && _names.TryGetValue(address, out var entry))
        {
            name = entry.Name;
            return true;
        }

        name = "";
        return false;
    }

    public string? GetNameOrNull(IPAddress? address) => TryGetName(address, out var name) ? name : null;

    /// <summary>Formats an endpoint for display: the domain when known, the address otherwise.</summary>
    public string Describe(IPAddress? address, ushort port)
    {
        string host = TryGetName(address, out var name) ? name : address?.ToString() ?? "";
        return port == 0 ? host : $"{host}:{port}";
    }

    public void Clear() => _names.Clear();
}
