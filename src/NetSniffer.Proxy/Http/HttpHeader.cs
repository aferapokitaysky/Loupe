namespace NetSniffer.Proxy.Http;

public readonly record struct HttpHeader(string Name, string Value);

public static class HttpHeaderListExtensions
{
    public static string? Get(this IReadOnlyList<HttpHeader> headers, string name)
    {
        foreach (var h in headers)
            if (string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase))
                return h.Value;
        return null;
    }

    public static bool Has(this IReadOnlyList<HttpHeader> headers, string name) =>
        headers.Any(h => string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase));
}
