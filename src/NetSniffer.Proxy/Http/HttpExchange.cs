namespace NetSniffer.Proxy.Http;

public enum ExchangeState { Pending, RequestSent, ResponseReceived, Failed }

/// <summary>
/// One HTTP request/response pair observed by the proxy. Mutated in place as
/// the exchange progresses (request captured, then response, then done) so
/// the UI can show a live "pending" row and update it - mutations happen on
/// the proxy's connection-handling task, reads happen from the UI thread, so
/// callers should treat the mutable fields as eventually-consistent snapshots
/// rather than something to react to synchronously.
/// </summary>
public sealed class HttpExchange
{
    public required long Id { get; init; }
    public required DateTimeOffset StartTime { get; init; }
    public required bool IsHttps { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }

    public string Method { get; set; } = "";
    public string PathAndQuery { get; set; } = "";
    public string HttpVersion { get; set; } = "";
    public List<HttpHeader> RequestHeaders { get; set; } = [];
    public byte[] RequestBody { get; set; } = [];
    public bool RequestBodyTruncated { get; set; }

    public int? StatusCode { get; set; }
    public string? ReasonPhrase { get; set; }
    public List<HttpHeader> ResponseHeaders { get; set; } = [];
    public byte[] ResponseBody { get; set; } = [];
    public bool ResponseBodyTruncated { get; set; }

    public ExchangeState State { get; set; } = ExchangeState.Pending;
    public string? Error { get; set; }
    public TimeSpan? Duration { get; set; }

    public string Scheme => IsHttps ? "https" : "http";
    public bool IsDefaultPort => (IsHttps && Port == 443) || (!IsHttps && Port == 80);
    public string Url => $"{Scheme}://{Host}{(IsDefaultPort ? "" : $":{Port}")}{PathAndQuery}";
}
