namespace NetSniffer.Proxy;

public sealed class ProxyOptions
{
    public int Port { get; init; } = 8080;
    public string ListenAddress { get; init; } = "127.0.0.1";

    /// <summary>How much of each request/response body to keep in memory for display; the rest is still relayed correctly, just not shown.</summary>
    public long MaxCapturedBodyBytes { get; init; } = 5 * 1024 * 1024;
}
