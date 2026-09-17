using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Loupe.Proxy.Http;

/// <summary>
/// Sends a captured request again, straight to the origin, and records the new answer as
/// another exchange. This is the "did that 500 just happen once?" tool: the same request,
/// unchanged, a minute later - and the two responses sitting next to each other.
///
/// Replays deliberately bypass any proxy, including this one. Going back out through the
/// proxy that captured the request would record the replay twice and make it impossible to
/// tell the original apart from its echo.
/// </summary>
public sealed class RequestReplayer : IDisposable
{
    /// <summary>Matches the proxy's own capture ceiling, so a replayed body is cut at the same place.</summary>
    private const long MaxCapturedBodyBytes = 5 * 1024 * 1024;

    private static readonly HashSet<string> SkippedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding",
        "Upgrade", "Content-Length", "Host",
    };

    private readonly HttpClient _client;

    public RequestReplayer(bool allowInsecureCertificates = false, TimeSpan? timeout = null)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false, // a redirect is an answer too; following it would hide it
            AutomaticDecompression = DecompressionMethods.None, // keep the bytes the server sent
        };

        if (allowInsecureCertificates)
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;

        _client = new HttpClient(handler) { Timeout = timeout ?? TimeSpan.FromSeconds(30) };
    }

    /// <summary>
    /// Re-sends <paramref name="original"/> and returns the result as a new exchange carrying
    /// <paramref name="id"/>. Never throws for a network failure: an unreachable host comes back
    /// as a failed exchange, the same shape the proxy records.
    /// </summary>
    public async Task<HttpExchange> ReplayAsync(HttpExchange original, long id, CancellationToken cancellationToken = default)
    {
        var replay = new HttpExchange
        {
            Id = id,
            StartTime = DateTimeOffset.Now,
            IsHttps = original.IsHttps,
            Host = original.Host,
            Port = original.Port,
            Client = original.Client,
            IsReplay = true,
            Method = original.Method,
            PathAndQuery = original.PathAndQuery,
            HttpVersion = original.HttpVersion,
            RequestHeaders = [.. original.RequestHeaders],
            RequestBody = original.RequestBody,
            State = ExchangeState.RequestSent,
        };

        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var request = BuildRequest(original);
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            replay.StatusCode = (int)response.StatusCode;
            replay.ReasonPhrase = response.ReasonPhrase;
            replay.HttpVersion = "HTTP/" + response.Version;
            replay.ResponseHeaders = [.. Flatten(response.Headers), .. Flatten(response.Content.Headers)];

            (replay.ResponseBody, replay.ResponseBodyTruncated) =
                await ReadCappedAsync(response, cancellationToken);

            replay.State = ExchangeState.ResponseReceived;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException
                                       or InvalidOperationException or UriFormatException or IOException)
        {
            replay.State = ExchangeState.Failed;
            replay.Error = ex is TaskCanceledException or OperationCanceledException
                ? "Timed out"
                : ex.Message;
        }

        replay.Duration = stopwatch.Elapsed;
        return replay;
    }

    private static HttpRequestMessage BuildRequest(HttpExchange original)
    {
        var request = new HttpRequestMessage(new HttpMethod(original.Method), original.Url)
        {
            // The capture may be HTTP/2; replaying over 1.1 keeps the request reproducible and
            // is what every origin still accepts. Upgrading is the server's call, not ours.
            Version = HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };

        if (original.RequestBody.Length > 0)
            request.Content = new ByteArrayContent(original.RequestBody);

        foreach (var header in original.RequestHeaders)
        {
            if (SkippedHeaders.Contains(header.Name)) continue;

            // Content headers live on the content in HttpClient's model and are rejected on the
            // request itself, so whatever the request refuses is offered to the body.
            if (!request.Headers.TryAddWithoutValidation(header.Name, header.Value))
                request.Content?.Headers.TryAddWithoutValidation(header.Name, header.Value);
        }

        return request;
    }

    private static async Task<(byte[] Body, bool Truncated)> ReadCappedAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();

        var chunk = new byte[81920];
        while (true)
        {
            int read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0) break;

            if (buffer.Length + read > MaxCapturedBodyBytes)
            {
                buffer.Write(chunk, 0, (int)(MaxCapturedBodyBytes - buffer.Length));
                return (buffer.ToArray(), true);
            }

            buffer.Write(chunk, 0, read);
        }

        return (buffer.ToArray(), false);
    }

    private static IEnumerable<HttpHeader> Flatten(HttpHeaders headers) =>
        headers.SelectMany(h => h.Value.Select(value => new HttpHeader(h.Key, value)));

    public void Dispose() => _client.Dispose();
}
