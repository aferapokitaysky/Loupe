using System.Net;

namespace Loupe.Core.Model;

/// <summary>Where a name-to-address association was observed.</summary>
public enum NameHintSource
{
    /// <summary>An A/AAAA answer in a DNS response - authoritative about the mapping.</summary>
    DnsAnswer,

    /// <summary>The SNI in a TLS ClientHello - names the host the client *intends* to reach.</summary>
    TlsSni,

    /// <summary>The Host header of a plaintext HTTP request.</summary>
    HttpHost,
}

/// <summary>
/// A name learned from the traffic itself: "this address is called that".
/// Collected while dissecting and fed to <see cref="Loupe.Core.Naming.HostNameRegistry"/>,
/// which is what turns raw IPs in the packet list into domains.
/// </summary>
/// <param name="Address">The address the name belongs to. Null when only the name is known
/// (an SNI seen before the address was resolved), in which case the packet's own peer
/// address is used by the registry.</param>
public readonly record struct HostNameHint(IPAddress? Address, string Name, NameHintSource Source);
