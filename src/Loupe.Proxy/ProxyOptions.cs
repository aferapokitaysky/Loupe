namespace Loupe.Proxy;

public sealed class ProxyOptions
{
    public int Port { get; init; } = 8080;
    public string ListenAddress { get; init; } = "127.0.0.1";

    /// <summary>
    /// Extra port that accepts raw, unproxied connections: no CONNECT line, the destination is
    /// taken from the TLS SNI or the HTTP Host header instead. This is how traffic from programs
    /// that ignore the Windows proxy setting gets captured - point them here (hosts file, their
    /// own config, a firewall rule) and they are intercepted like any browser. 0 disables it.
    /// </summary>
    public int TransparentPort { get; init; }

    /// <summary>
    /// Port to connect to upstream for a transparent TLS connection. 443 is right for redirected
    /// browser/app traffic; it is configurable because a service on a non-standard TLS port is
    /// exactly the kind of thing that ignores the system proxy and needs intercepting this way.
    /// </summary>
    public int TransparentTlsUpstreamPort { get; init; } = 443;

    /// <summary>
    /// Skip certificate validation on the proxy's own connection to the real server.
    ///
    /// Off by default, and it should stay off: the proxy verifying upstream is the only thing
    /// standing between the client and a server impersonating the one it asked for - the client
    /// itself can no longer tell, because it is talking to us. Turn it on only to debug a server
    /// you control that has a self-signed or expired certificate.
    /// </summary>
    public bool AllowInsecureUpstream { get; init; }

    /// <summary>
    /// Optional: identifies the program behind an accepted connection, given the client's
    /// endpoint. Called once per connection, while the socket is still open (the OS forgets the
    /// owner the moment it closes). Left to the host because it is platform-specific.
    /// </summary>
    public Func<System.Net.EndPoint?, Http.ClientApplication?>? ResolveClientApplication { get; init; }

    /// <summary>How much of each request/response body to keep in memory for display; the rest is still relayed correctly, just not shown.</summary>
    public long MaxCapturedBodyBytes { get; init; } = 5 * 1024 * 1024;
}
