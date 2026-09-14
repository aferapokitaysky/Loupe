using System.Text;

namespace NetSniffer.Proxy.Http;

public sealed record RequestHead(string Method, string Target, string Version, List<HttpHeader> Headers);
public sealed record ResponseHead(string Version, int StatusCode, string ReasonPhrase, List<HttpHeader> Headers);

public sealed class ProxyProtocolException(string message) : Exception(message);

public enum BodyFraming { None, ContentLength, Chunked, UntilClose }

/// <summary>Reads/writes HTTP/1.x request-line+headers and status-line+headers.</summary>
public static class HttpMessageIo
{
    /// <summary>
    /// Null return means the connection was idle/closed at a message boundary - a normal keep-alive
    /// end, not an error. Pass <paramref name="firstLineOverride"/> when the caller already consumed
    /// the request line off the reader (e.g. to sniff CONNECT vs. a plain proxied request).
    /// </summary>
    public static async Task<RequestHead?> ReadRequestHeadAsync(HttpLineReader reader, CancellationToken ct, string? firstLineOverride = null)
    {
        string? requestLine = firstLineOverride ?? await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(requestLine)) return null;

        var parts = requestLine.Split(' ', 3);
        if (parts.Length != 3)
            throw new ProxyProtocolException($"Malformed request line: '{requestLine}'");

        var headers = await ReadHeadersAsync(reader, ct).ConfigureAwait(false);
        return new RequestHead(parts[0], parts[1], parts[2], headers);
    }

    public static async Task<ResponseHead> ReadResponseHeadAsync(HttpLineReader reader, CancellationToken ct)
    {
        string? statusLine = await reader.ReadLineAsync(ct).ConfigureAwait(false)
            ?? throw new ProxyProtocolException("Upstream closed the connection before sending a response.");

        var parts = statusLine.Split(' ', 3);
        if (parts.Length < 2 || !int.TryParse(parts[1], out int statusCode))
            throw new ProxyProtocolException($"Malformed status line: '{statusLine}'");

        string reason = parts.Length > 2 ? parts[2] : "";
        var headers = await ReadHeadersAsync(reader, ct).ConfigureAwait(false);
        return new ResponseHead(parts[0], statusCode, reason, headers);
    }

    private static async Task<List<HttpHeader>> ReadHeadersAsync(HttpLineReader reader, CancellationToken ct)
    {
        var headers = new List<HttpHeader>();
        while (true)
        {
            string? line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(line)) break;

            int colon = line.IndexOf(':');
            if (colon <= 0) continue; // tolerate/skip malformed header lines rather than aborting the whole exchange
            headers.Add(new HttpHeader(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
        return headers;
    }

    public static Task WriteRequestLineAndHeadersAsync(Stream destination, string method, string target, string version, IEnumerable<HttpHeader> headers, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(target).Append(' ').Append(version).Append("\r\n");
        AppendHeaders(sb, headers);
        return WriteAsciiAsync(destination, sb.ToString(), ct);
    }

    public static Task WriteResponseLineAndHeadersAsync(Stream destination, string version, int statusCode, string reasonPhrase, IEnumerable<HttpHeader> headers, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append(version).Append(' ').Append(statusCode).Append(' ').Append(reasonPhrase).Append("\r\n");
        AppendHeaders(sb, headers);
        return WriteAsciiAsync(destination, sb.ToString(), ct);
    }

    private static void AppendHeaders(StringBuilder sb, IEnumerable<HttpHeader> headers)
    {
        foreach (var h in headers)
            sb.Append(h.Name).Append(": ").Append(h.Value).Append("\r\n");
        sb.Append("\r\n");
    }

    private static Task WriteAsciiAsync(Stream destination, string text, CancellationToken ct) =>
        destination.WriteAsync(Encoding.Latin1.GetBytes(text), ct).AsTask();

    /// <summary>Determines how a message body is framed per RFC 7230 §3.3.3, in priority order.</summary>
    public static (BodyFraming Framing, long ContentLength) DetermineBodyFraming(IReadOnlyList<HttpHeader> headers, bool allowUntilClose)
    {
        string? transferEncoding = headers.Get("Transfer-Encoding");
        if (transferEncoding != null && transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            return (BodyFraming.Chunked, 0);

        string? contentLength = headers.Get("Content-Length");
        if (contentLength != null && long.TryParse(contentLength, out long length))
            return length > 0 ? (BodyFraming.ContentLength, length) : (BodyFraming.None, 0);

        return allowUntilClose ? (BodyFraming.UntilClose, 0) : (BodyFraming.None, 0);
    }
}
