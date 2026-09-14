using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using NetSniffer.Proxy.Ca;
using NetSniffer.Proxy.Http;

namespace NetSniffer.Proxy;

/// <summary>
/// A local HTTP/HTTPS debugging proxy in the Charles/Fiddler/Proxyman mold:
/// clients (browsers, curl, mobile apps on the same network, ...) are
/// pointed at this proxy; plain HTTP requests are relayed directly, and
/// HTTPS is intercepted via CONNECT - the proxy terminates TLS towards the
/// client with a certificate minted on the fly by <see cref="RootCertificateAuthority"/>
/// and opens its own, separately verified TLS connection to the real server.
///
/// This only works, and is only meant to work, on traffic that is
/// deliberately routed through it AND on a client that has chosen to trust
/// the locally-generated root CA - i.e. your own devices/apps, configured by
/// you for debugging. It cannot intercept anything else.
/// </summary>
public sealed class ProxyServer : IDisposable
{
    private static readonly HashSet<string> HopByHopHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate",
    };

    private readonly ProxyOptions _options;
    private readonly LeafCertificateFactory _leafCertificates;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private long _nextExchangeId;

    public event EventHandler<HttpExchange>? ExchangeStarted;
    public event EventHandler<HttpExchange>? ExchangeUpdated;
    public event EventHandler<string>? ConnectionError;

    public bool IsRunning { get; private set; }

    public ProxyServer(ProxyOptions options, RootCertificateAuthority ca)
    {
        _options = options;
        _leafCertificates = new LeafCertificateFactory(ca);
    }

    public void Start()
    {
        if (IsRunning) throw new InvalidOperationException("Proxy is already running.");

        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Parse(_options.ListenAddress), _options.Port);
        _listener.Start();
        IsRunning = true;
        _ = AcceptLoopAsync(_cts.Token);
    }

    public void Stop()
    {
        IsRunning = false;
        try { _cts?.Cancel(); } catch { /* already disposed */ }
        try { _listener?.Stop(); } catch { /* already stopped */ }
    }

    public void Dispose() => Stop();

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await _listener!.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = HandleClientAsync(client, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using var disposeClient = client;
        client.NoDelay = true;
        await using var clientStream = client.GetStream();
        var reader = new HttpLineReader(clientStream);

        try
        {
            string? firstLine = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(firstLine)) return;

            var parts = firstLine.Split(' ', 3);
            if (parts.Length != 3) return;

            if (string.Equals(parts[0], "CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                await HandleConnectAsync(parts[1], reader, clientStream, ct).ConfigureAwait(false);
            }
            else if (Uri.TryCreate(parts[1], UriKind.Absolute, out _))
            {
                var head = await HttpMessageIo.ReadRequestHeadAsync(reader, ct, firstLineOverride: firstLine).ConfigureAwait(false);
                if (head is not null)
                    await RelayPlainHttpLoopAsync(head, reader, clientStream, ct).ConfigureAwait(false);
            }
            // else: not a valid proxy request (e.g. someone opened the proxy port directly in a browser) - just close.
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ConnectionError?.Invoke(this, ex.Message);
        }
    }

    private async Task HandleConnectAsync(string authority, HttpLineReader clientReader, Stream rawClientStream, CancellationToken ct)
    {
        // Drain the rest of the CONNECT request's headers - nothing in them matters for tunneling.
        while (true)
        {
            string? line = await clientReader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(line)) break;
        }

        var (host, port) = ParseAuthority(authority, defaultPort: 443);

        byte[] ok = Encoding.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
        await rawClientStream.WriteAsync(ok, ct).ConfigureAwait(false);

        var leafCertificate = _leafCertificates.GetOrCreate(host);

        await using var sslStream = new SslStream(rawClientStream, leaveInnerStreamOpen: false);
        try
        {
            await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leafCertificate,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                EnabledSslProtocols = SslProtocols.None,
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Almost always means the client doesn't trust our root CA yet.
            ConnectionError?.Invoke(this, $"TLS handshake with client failed for {host}: {ex.Message}");
            return;
        }

        var tlsReader = new HttpLineReader(sslStream);
        await RelayHttpsLoopAsync(tlsReader, sslStream, host, port, ct).ConfigureAwait(false);
    }

    private async Task RelayHttpsLoopAsync(HttpLineReader clientReader, Stream clientStream, string host, int port, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var head = await HttpMessageIo.ReadRequestHeadAsync(clientReader, ct).ConfigureAwait(false);
            if (head is null) return;

            var exchange = NewExchange(isHttps: true, host, port, head);
            if (!await RunExchangeAsync(exchange, clientReader, clientStream, ct).ConfigureAwait(false))
                return;
        }
    }

    private async Task RelayPlainHttpLoopAsync(RequestHead firstHead, HttpLineReader clientReader, Stream clientStream, CancellationToken ct)
    {
        RequestHead? head = firstHead;
        while (head is not null && !ct.IsCancellationRequested)
        {
            if (!Uri.TryCreate(head.Target, UriKind.Absolute, out var uri))
                return;

            var normalized = head with { Target = uri.PathAndQuery };
            var exchange = NewExchange(isHttps: false, uri.Host, uri.Port, normalized);
            if (!await RunExchangeAsync(exchange, clientReader, clientStream, ct).ConfigureAwait(false))
                return;

            head = await HttpMessageIo.ReadRequestHeadAsync(clientReader, ct).ConfigureAwait(false);
        }
    }

    private HttpExchange NewExchange(bool isHttps, string host, int port, RequestHead head) => new()
    {
        Id = Interlocked.Increment(ref _nextExchangeId),
        StartTime = DateTimeOffset.Now,
        IsHttps = isHttps,
        Host = host,
        Port = port,
        Method = head.Method,
        PathAndQuery = head.Target,
        HttpVersion = head.Version,
        RequestHeaders = head.Headers,
    };

    /// <summary>Runs one request/response exchange end to end. Returns whether the client connection should stay open for another request.</summary>
    private async Task<bool> RunExchangeAsync(HttpExchange exchange, HttpLineReader clientReader, Stream clientStream, CancellationToken ct)
    {
        ExchangeStarted?.Invoke(this, exchange);

        try
        {
            bool keepAlive = await RelayOneExchangeAsync(exchange, clientReader, clientStream, ct).ConfigureAwait(false);
            ExchangeUpdated?.Invoke(this, exchange);
            return keepAlive;
        }
        catch (Exception ex)
        {
            exchange.State = ExchangeState.Failed;
            exchange.Error = ex.Message;
            exchange.Duration = DateTimeOffset.Now - exchange.StartTime;
            ExchangeUpdated?.Invoke(this, exchange);
            return false;
        }
    }

    private async Task<bool> RelayOneExchangeAsync(HttpExchange exchange, HttpLineReader clientReader, Stream clientStream, CancellationToken ct)
    {
        using var upstreamClient = new TcpClient();
        await upstreamClient.ConnectAsync(exchange.Host, exchange.Port, ct).ConfigureAwait(false);

        Stream upstreamStream = upstreamClient.GetStream();
        if (exchange.IsHttps)
        {
            var upstreamSsl = new SslStream(upstreamStream, leaveInnerStreamOpen: false);
            await upstreamSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = exchange.Host,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            }, ct).ConfigureAwait(false);
            upstreamStream = upstreamSsl; // SslStream(leaveInnerStreamOpen: false) disposes the underlying NetworkStream too
        }

        await using var _ = upstreamStream;

        await HttpMessageIo.WriteRequestLineAndHeadersAsync(
            upstreamStream, exchange.Method, exchange.PathAndQuery, exchange.HttpVersion,
            FilterHopByHop(exchange.RequestHeaders), ct).ConfigureAwait(false);

        var (requestFraming, requestLength) = HttpMessageIo.DetermineBodyFraming(exchange.RequestHeaders, allowUntilClose: false);
        var requestCapture = await RelayBodyAsync(requestFraming, requestLength, clientReader, upstreamStream, ct).ConfigureAwait(false);
        exchange.RequestBody = requestCapture.CapturedBytes;
        exchange.RequestBodyTruncated = requestCapture.Truncated;
        exchange.State = ExchangeState.RequestSent;
        ExchangeUpdated?.Invoke(this, exchange);

        var upstreamReader = new HttpLineReader(upstreamStream);
        var responseHead = await HttpMessageIo.ReadResponseHeadAsync(upstreamReader, ct).ConfigureAwait(false);

        exchange.StatusCode = responseHead.StatusCode;
        exchange.ReasonPhrase = responseHead.ReasonPhrase;
        exchange.ResponseHeaders = responseHead.Headers;

        await HttpMessageIo.WriteResponseLineAndHeadersAsync(
            clientStream, responseHead.Version, responseHead.StatusCode, responseHead.ReasonPhrase,
            FilterHopByHop(responseHead.Headers), ct).ConfigureAwait(false);

        bool responseHasNoBody = exchange.Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase)
            || responseHead.StatusCode is 204 or 304;
        var (responseFraming, responseLength) = responseHasNoBody
            ? (BodyFraming.None, 0L)
            : HttpMessageIo.DetermineBodyFraming(responseHead.Headers, allowUntilClose: true);

        var responseCapture = await RelayBodyAsync(responseFraming, responseLength, upstreamReader, clientStream, ct).ConfigureAwait(false);
        exchange.ResponseBody = responseCapture.CapturedBytes;
        exchange.ResponseBodyTruncated = responseCapture.Truncated;
        exchange.State = ExchangeState.ResponseReceived;
        exchange.Duration = DateTimeOffset.Now - exchange.StartTime;

        bool clientKeepAlive = !ConnectionHeaderSaysClose(exchange.RequestHeaders, exchange.HttpVersion);
        bool serverKeepAlive = !ConnectionHeaderSaysClose(responseHead.Headers, responseHead.Version) && responseFraming != BodyFraming.UntilClose;
        return clientKeepAlive && serverKeepAlive;
    }

    private Task<CaptureResult> RelayBodyAsync(BodyFraming framing, long length, HttpLineReader source, Stream destination, CancellationToken ct)
    {
        long limit = _options.MaxCapturedBodyBytes;
        return framing switch
        {
            BodyFraming.ContentLength => BodyRelay.CopyContentLengthAsync(source, destination, length, limit, ct),
            BodyFraming.Chunked => BodyRelay.CopyChunkedAsync(source, destination, limit, ct),
            BodyFraming.UntilClose => BodyRelay.CopyUntilCloseAsync(source, destination, limit, ct),
            _ => Task.FromResult(new CaptureResult([], Truncated: false)),
        };
    }

    private static List<HttpHeader> FilterHopByHop(IEnumerable<HttpHeader> headers) =>
        headers.Where(h => !HopByHopHeaderNames.Contains(h.Name)).ToList();

    private static bool ConnectionHeaderSaysClose(IReadOnlyList<HttpHeader> headers, string version)
    {
        string? connection = headers.Get("Connection");
        if (connection != null) return connection.Contains("close", StringComparison.OrdinalIgnoreCase);
        return version.Equals("HTTP/1.0", StringComparison.OrdinalIgnoreCase);
    }

    private static (string Host, int Port) ParseAuthority(string authority, int defaultPort)
    {
        int colon = authority.LastIndexOf(':');
        if (colon > 0 && int.TryParse(authority[(colon + 1)..], out int port))
            return (authority[..colon], port);
        return (authority, defaultPort);
    }
}
