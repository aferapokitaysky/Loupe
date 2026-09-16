using System.IO;
using System.Text.Json;
using Loupe.Proxy.Http;

namespace Loupe.App.Services;

/// <summary>
/// Reads and writes the proxy's requests inside a saved session.
///
/// Bodies are kept, because a request without its body is rarely worth keeping - but capped, so
/// one video download doesn't turn a session into a gigabyte on disk. What was cut is recorded
/// rather than quietly dropped.
/// </summary>
public static class ProxySessionFile
{
    private const int MaxSavedBodyBytes = 512 * 1024;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public static void Save(string path, IEnumerable<HttpExchange> exchanges)
    {
        var saved = exchanges.Select(e => new SavedExchange(
            e.Id,
            e.StartTime,
            e.Method,
            e.Scheme,
            e.Host,
            e.Port,
            e.PathAndQuery,
            e.HttpVersion,
            e.StatusCode,
            e.ReasonPhrase,
            e.State.ToString(),
            e.Error,
            e.Duration?.TotalMilliseconds,
            e.Client?.Name,
            e.Client?.ImagePath,
            Pairs(e.RequestHeaders),
            Convert.ToBase64String(Cap(e.RequestBody, out bool requestCut)),
            e.RequestBodyTruncated || requestCut,
            Pairs(e.ResponseHeaders),
            Convert.ToBase64String(Cap(e.ResponseBody, out bool responseCut)),
            e.ResponseBodyTruncated || responseCut)).ToList();

        using var stream = File.Create(path);
        JsonSerializer.Serialize(stream, saved, Json);
    }

    /// <summary>Returns the exchanges in the file, or an empty list if it can't be read.</summary>
    public static List<HttpExchange> Load(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            var saved = JsonSerializer.Deserialize<List<SavedExchange>>(stream) ?? [];

            return saved.Select(s => new HttpExchange
            {
                Id = s.Id,
                StartTime = s.StartTime,
                IsHttps = string.Equals(s.Scheme, "https", StringComparison.OrdinalIgnoreCase),
                Host = s.Host,
                Port = s.Port,
                Method = s.Method,
                PathAndQuery = s.PathAndQuery,
                HttpVersion = s.HttpVersion,
                StatusCode = s.StatusCode,
                ReasonPhrase = s.ReasonPhrase,
                State = Enum.TryParse<ExchangeState>(s.State, out var state) ? state : ExchangeState.ResponseReceived,
                Error = s.Error,
                Duration = s.DurationMs is { } ms ? TimeSpan.FromMilliseconds(ms) : null,
                Client = s.ClientName is null ? null : new ClientApplication(s.ClientName, s.ClientImagePath),
                RequestHeaders = Headers(s.RequestHeaders),
                RequestBody = Decode(s.RequestBodyBase64),
                RequestBodyTruncated = s.RequestBodyTruncated,
                ResponseHeaders = Headers(s.ResponseHeaders),
                ResponseBody = Decode(s.ResponseBodyBase64),
                ResponseBodyTruncated = s.ResponseBodyTruncated,
            }).ToList();
        }
        catch (Exception e) when (e is IOException or JsonException or FormatException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static List<string[]> Pairs(IEnumerable<HttpHeader> headers) =>
        headers.Select(h => new[] { h.Name, h.Value }).ToList();

    private static List<HttpHeader> Headers(List<string[]>? pairs) =>
        pairs?.Where(p => p.Length == 2).Select(p => new HttpHeader(p[0], p[1])).ToList() ?? [];

    private static byte[] Cap(byte[] body, out bool truncated)
    {
        truncated = body.Length > MaxSavedBodyBytes;
        return truncated ? body[..MaxSavedBodyBytes] : body;
    }

    private static byte[] Decode(string? base64) =>
        string.IsNullOrEmpty(base64) ? [] : Convert.FromBase64String(base64);

    private sealed record SavedExchange(
        long Id, DateTimeOffset StartTime, string Method, string Scheme, string Host, int Port,
        string PathAndQuery, string HttpVersion, int? StatusCode, string? ReasonPhrase, string State,
        string? Error, double? DurationMs, string? ClientName, string? ClientImagePath,
        List<string[]> RequestHeaders, string RequestBodyBase64, bool RequestBodyTruncated,
        List<string[]> ResponseHeaders, string ResponseBodyBase64, bool ResponseBodyTruncated);
}
