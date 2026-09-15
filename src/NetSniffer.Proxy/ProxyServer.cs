using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using NetSniffer.Proxy.Ca;
using NetSniffer.Proxy.Http;
using NetSniffer.Proxy.Transparent;

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
    private TcpListener? _transparentListener;
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
        _ = AcceptLoopAsync(_listener, explicitProxy: true, _cts.Token);

        if (_options.TransparentPort > 0)
        {
            _transparentListener = new TcpListener(IPAddress.Parse(_options.ListenAddress), _options.TransparentPort);
            _transparentListener.Start();
            _ = AcceptLoopAsync(_transparentListener, explicitProxy: false, _cts.Token);
        }
    }

    public void Stop()
    {
        IsRunning = false;
        try { _cts?.Cancel(); } catch { /* already disposed */ }
        try { _listener?.Stop(); } catch { /* already stopped */ }
        try { _transparentListener?.Stop(); } catch { /* already stopped */ }
        try { _cts?.Dispose(); } catch { /* already disposed */ }
        _cts = null;
        _listener = null;
        _transparentListener = null;
    }

    public void Dispose() => Stop();

    private async Task AcceptLoopAsync(TcpListener listener, bool explicitProxy, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = explicitProxy
                    ? HandleClientAsync(client, ct)
                    : HandleTransparentClientAsync(client, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
    }

    /// <summary>
    /// Handles a connection that arrived with no proxy protocol at all - the client believes it
    /// is talking to the origin server. The destination comes from the TLS SNI, or from the Host
    /// header for plaintext HTTP, and the peeked bytes are replayed so the real handshake sees
    /// exactly what the client sent.
    /// </summary>
    private async Task HandleTransparentClientAsync(TcpClient client, CancellationToken ct)
    {
        using var disposeClient = client;
        client.NoDelay = true;
        await using var socketStream = client.GetStream();

        try
        {
            // One ClientHello fits comfortably; a larger one (many extensions) still gives us
            // the SNI, which sits near the front.
            var peeked = new byte[4096];
            int read = await socketStream.ReadAsync(peeked.AsMemory(), ct).ConfigureAwait(false);
            if (read <= 0) return;

            var prefix = peeked[..read];
            var stream = new PrefixedStream(prefix, socketStream);

            if (ClientHelloSniffer.LooksLikeTls(prefix))
            {
                if (!ClientHelloSniffer.TryGetServerName(prefix, out string sni))
                {
                    // No SNI means nothing in the connection says where it was going, and a
                    // transparent proxy has no other source for that.
                    ConnectionError?.Invoke(this, "Transparent TLS connection without an SNI - cannot tell which host it was for.");
                    return;
                }

                await InterceptTransparentTlsAsync(stream, sni, ct).ConfigureAwait(false);
                return;
            }

            // Plaintext: origin-form request line plus a Host header.
            var reader = new HttpLineReader(stream);
            var head = await HttpMessageIo.ReadRequestHeadAsync(reader, ct).ConfigureAwait(false);
            if (head is null) return;

            var hostHeaders = head.Headers
                .Where(h => string.Equals(h.Name, "Host", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (hostHeaders.Count == 0) return;

            string hostHeader = hostHeaders[0].Value;
            if (string.IsNullOrWhiteSpace(hostHeader)) return;

            var (host, port) = ParseAuthority(hostHeader, defaultPort: 80);
            await RelayTransparentPlainHttpLoopAsync(head, reader, stream, host, port, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ConnectionError?.Invoke(this, ex.Message);
        }
    }

    private async Task InterceptTransparentTlsAsync(Stream clientStream, string host, CancellationToken ct)
    {
        var leafCertificate = _leafCertificates.GetOrCreate(host);

        await using var sslStream = new SslStream(clientStream, leaveInnerStreamOpen: false);
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
            ConnectionError?.Invoke(this, $"TLS handshake with client failed for {host}: {ex.Message}");
            return;
        }

        var tlsReader = new HttpLineReader(sslStream);
        await RelayHttpsLoopAsync(tlsReader, sslStream, host, _options.TransparentTlsUpstreamPort, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Like the proxy-style plaintext loop, but the request line is origin-form ("/path"), so
    /// the destination is carried alongside instead of being parsed out of an absolute URL.
    /// </summary>
    private async Task RelayTransparentPlainHttpLoopAsync(
        RequestHead firstHead, HttpLineReader clientReader, Stream clientStream,
        string host, int port, CancellationToken ct)
    {
        RequestHead? head = firstHead;
        while (head is not null && !ct.IsCancellationRequested)
        {
            var exchange = NewExchange(isHttps: false, host, port, head);
            if (!await RunExchangeAsync(exchange, clientReader, clientStream, ct).ConfigureAwait(false))
                return;

            head = await HttpMessageIo.ReadRequestHeadAsync(clientReader, ct).ConfigureAwait(false);
        }
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
            // The client can no longer check the server itself - it is talking to us - so this
            // leg is verified normally unless the user explicitly opted out.
            var upstreamSsl = _options.AllowInsecureUpstream
                ? new SslStream(upstreamStream, leaveInnerStreamOpen: false, (_, _, _, _) => true)
                : new SslStream(upstreamStream, leaveInnerStreamOpen: false);

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
