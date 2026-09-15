using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetSniffer.Proxy;
using NetSniffer.Proxy.Ca;
using NetSniffer.Proxy.Http;
using NetSniffer.Proxy.Transparent;

/// <summary>
/// Transparent interception: traffic from a client that was never told about a proxy, which is
/// how programs that ignore the Windows proxy setting get captured.
/// </summary>
public static class TransparentTests
{
    public static async Task RunAsync()
    {
        T.Section("TRANSPARENT MODE (client sends no CONNECT, no proxy configured)");

        // ---- SNI sniffing, the only thing naming the destination in a transparent TLS connection
        byte[] hello = B.TlsClientHello("example.org");
        T.Check("ClientHello recognised as TLS", ClientHelloSniffer.LooksLikeTls(hello));
        T.Check("SNI read out of the ClientHello",
            ClientHelloSniffer.TryGetServerName(hello, out string sni) && sni == "example.org", sni);

        T.Check("plain HTTP is not mistaken for TLS",
            !ClientHelloSniffer.LooksLikeTls(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n")));
        T.Check("truncated ClientHello is refused, not guessed",
            !ClientHelloSniffer.TryGetServerName(hello.AsSpan(0, 20), out _));

        // ---- The peeked bytes have to be replayed or the real handshake sees a truncated stream
        var source = new MemoryStream("world"u8.ToArray());
        var prefixed = new PrefixedStream("hello "u8.ToArray(), source);
        using (var reader = new StreamReader(prefixed, Encoding.ASCII))
            T.Eq("peeked prefix is replayed ahead of the live stream", "hello world", await reader.ReadToEndAsync());

        // ---- End to end: a client that thinks it is talking straight to the origin
        var origin = new RawHttpServer();
        int originPort = origin.Start();

        string caDir = Path.Combine(Path.GetTempPath(), "ns-ca-tp-" + Guid.NewGuid().ToString("N"));
        var ca = new RootCertificateAuthority(caDir);
        var exchanges = new List<HttpExchange>();

        // The TLS origin comes up first so the proxy can be told which upstream port a
        // transparent TLS connection should go to (443 in the real world).
        var tlsOrigin = new TlsEchoServer(ca.Certificate);
        int tlsPort = tlsOrigin.Start();

        var proxy = new ProxyServer(
            new ProxyOptions
            {
                Port = 18795,
                TransparentPort = 18796,
                TransparentTlsUpstreamPort = tlsPort,
                // The test origin's certificate is issued by the throwaway CA, which is not in
                // the machine's trust store - exactly the case this switch exists for.
                AllowInsecureUpstream = true,
            },
            ca);
        proxy.ExchangeUpdated += (_, e) =>
        {
            if (e.State is ExchangeState.ResponseReceived or ExchangeState.Failed)
                lock (exchanges) exchanges.Add(e);
        };
        proxy.Start();

        // No WebProxy anywhere: the request is addressed to the transparent port directly, the
        // way a redirected connection arrives. The Host header is what names the destination.
        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, 18796);
            await using var stream = client.GetStream();

            byte[] request = Encoding.ASCII.GetBytes(
                $"GET /len HTTP/1.1\r\nHost: 127.0.0.1:{originPort}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(request);

            using var reader = new StreamReader(stream, Encoding.ASCII);
            string response = await reader.ReadToEndAsync();

            T.Check("transparent HTTP relayed a real response", response.Contains("hello-len"), Summarize(response));
            T.Check("transparent response kept its status line", response.StartsWith("HTTP/1.1 200"), Summarize(response));
        }

        await Task.Delay(500);

        lock (exchanges)
        {
            var captured = exchanges.FirstOrDefault(e => e.PathAndQuery == "/len");
            T.Check("transparent exchange captured", captured is not null);
            T.Eq("captured with the Host header's destination", "127.0.0.1", captured?.Host ?? "");
            T.Eq("captured status", 200, captured?.StatusCode ?? 0);
            T.Eq("captured body", "hello-len", Encoding.UTF8.GetString(captured?.ResponseBody ?? []));
            T.Check("captured as plaintext, not https", captured?.IsHttps == false);
        }

        // ---- TLS through the transparent port: the point of the exercise. The client is given
        // no proxy at all; it dials the transparent port believing it is the origin, and the
        // only thing naming the real destination is the SNI it sends.
        bool tlsIntercepted = false;
        string interceptedBody = "";
        try
        {
            using var handler = new HttpClientHandler
            {
                // The client trusts our CA, exactly as it would after installing the root
                // certificate - that consent is what makes interception possible at all.
                ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                    cert is not null && cert.Issuer == ca.Certificate.Subject,
            };
            using var https = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            interceptedBody = await https.GetStringAsync($"https://localhost:18796/tls");
            tlsIntercepted = true;
        }
        catch (Exception ex)
        {
            interceptedBody = ex.Message;
        }

        T.Check("transparent TLS intercepted and relayed to the SNI's host",
            tlsIntercepted && interceptedBody.Contains("tls-ok"), Summarize(interceptedBody));

        await Task.Delay(500);
        lock (exchanges)
        {
            var tls = exchanges.FirstOrDefault(e => e.PathAndQuery == "/tls");
            T.Check("transparent TLS exchange captured in the clear", tls is not null);
            T.Eq("captured host came from the SNI", "localhost", tls?.Host ?? "");
            T.Check("captured as https", tls?.IsHttps == true);
            T.Eq("decrypted response body captured", "tls-ok", Encoding.UTF8.GetString(tls?.ResponseBody ?? []));
        }

        proxy.Stop();
        origin.Stop();
        tlsOrigin.Stop();
        try { Directory.Delete(caDir, true); } catch { }
    }

    private static string Summarize(string text) =>
        text.Length <= 120 ? text.Replace("\r\n", "\\n") : text[..120].Replace("\r\n", "\\n") + "...";
}

/// <summary>A minimal HTTPS origin used to prove the TLS path end to end.</summary>
public sealed class TlsEchoServer(X509Certificate2 certificate)
{
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public int Start()
    {
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _ = AcceptAsync(_cts.Token);
        return ((IPEndPoint)_listener.LocalEndpoint).Port;
    }

    public void Stop() { _cts?.Cancel(); try { _listener?.Stop(); } catch { } }

    private async Task AcceptAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                _ = HandleAsync(client, ct);
            }
        }
        catch { }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                }, ct);

                var buffer = new byte[4096];
                await ssl.ReadAsync(buffer, ct);

                byte[] response = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-ok");
                await ssl.WriteAsync(response, ct);
                await ssl.FlushAsync(ct);
            }
            catch { }
        }
    }
}
