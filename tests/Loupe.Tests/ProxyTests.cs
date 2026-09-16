using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using Loupe.Proxy;
using Loupe.Proxy.Ca;
using Loupe.Proxy.Http;

public static class ProxyTests
{
    public static async Task RunAsync()
    {
        T.Section("PROXY RELAY (against a byte-exact local HTTP server)");

        var origin = new RawHttpServer();
        int originPort = origin.Start();

        string caDir = Path.Combine(Path.GetTempPath(), "ns-ca-" + Guid.NewGuid().ToString("N"));
        var ca = new RootCertificateAuthority(caDir);
        var exchanges = new List<HttpExchange>();
        // The real Windows resolver: the HttpClient below runs in this process, so this process
        // is what every exchange must be attributed to.
        var proxy = new ProxyServer(new ProxyOptions
        {
            Port = 18777,
            ResolveClientApplication = endPoint =>
                Loupe.Capture.Processes.ProcessPortMap.Shared.LookupTcpClient(endPoint) is { } owner
                    ? new ClientApplication(owner.Name, owner.ImagePath)
                    : null,
        }, ca);
        proxy.ExchangeUpdated += (_, e) =>
        {
            if (e.State is ExchangeState.ResponseReceived or ExchangeState.Failed)
                lock (exchanges) exchanges.Add(e);
        };
        proxy.Start();

        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy("http://127.0.0.1:18777"),
            UseProxy = true,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        string Root(string path) => "http://127.0.0.1:" + originPort + path;

        var r1 = await http.GetAsync(Root("/len"));
        T.Eq("Content-Length body relayed intact", "hello-len", await r1.Content.ReadAsStringAsync());

        var r2 = await http.GetAsync(Root("/chunked"));
        T.Eq("chunked body relayed intact", "abcdefgh", await r2.Content.ReadAsStringAsync());

        var r3 = await http.GetAsync(Root("/gzip"));
        T.Eq("gzip body decodes end-to-end", "gzip-payload-0123456789", await r3.Content.ReadAsStringAsync());

        var r4 = await http.GetAsync(Root("/204"));
        T.Eq("204 status relayed", 204, (int)r4.StatusCode);

        var r5 = await http.SendAsync(new HttpRequestMessage(HttpMethod.Head, Root("/len")));
        T.Eq("HEAD status relayed", 200, (int)r5.StatusCode);
        T.Eq("HEAD returns no body", 0, (await r5.Content.ReadAsByteArrayAsync()).Length);

        var r6 = await http.PostAsync(Root("/echo"), new StringContent("payload-42"));
        T.Eq("POST body echoed through proxy", "payload-42", await r6.Content.ReadAsStringAsync());

        bool keepAliveOk = true;
        for (int i = 0; i < 3; i++)
        {
            var rk = await http.GetAsync(Root("/len"));
            if ((int)rk.StatusCode != 200) { keepAliveOk = false; break; }
        }
        T.Check("keep-alive: 3 more requests on the same client connection", keepAliveOk);

        // Upstream refuses the connection: must surface as a failed exchange, not a hang.
        try { await http.GetAsync("http://127.0.0.1:9/dead"); } catch { }

        await Task.Delay(600);
        proxy.Stop();
        origin.Stop();

        lock (exchanges)
        {
            T.Check("exchanges captured for every request", exchanges.Count >= 8, "got " + exchanges.Count);

            var len = exchanges.First(e => e.PathAndQuery == "/len" && e.Method == "GET");
            T.Eq("captured status code", 200, len.StatusCode);
            T.Eq("captured response body", "hello-len", Encoding.UTF8.GetString(len.ResponseBody));
            T.Eq("captured scheme", "http", len.Scheme);
            T.Eq("request attributed to the program that sent it",
                System.Diagnostics.Process.GetCurrentProcess().ProcessName, len.Client?.Name ?? "(none)");
            T.Check("captured URL shaped correctly", len.Url.StartsWith("http://127.0.0.1:"), len.Url);

            var chunked = exchanges.First(e => e.PathAndQuery == "/chunked");
            T.Eq("chunked capture is de-chunked payload only", "abcdefgh", Encoding.UTF8.GetString(chunked.ResponseBody));

            var gz = exchanges.First(e => e.PathAndQuery == "/gzip");
            T.Check("gzip capture keeps the raw compressed bytes",
                gz.ResponseBody.Length >= 2 && gz.ResponseBody[0] == 0x1F && gz.ResponseBody[1] == 0x8B,
                BitConverter.ToString(gz.ResponseBody.Take(4).ToArray()));
            using (var ms = new MemoryStream(gz.ResponseBody))
            using (var gzs = new GZipStream(ms, CompressionMode.Decompress))
            using (var sr = new StreamReader(gzs))
                T.Eq("captured gzip decompresses to the original", "gzip-payload-0123456789", sr.ReadToEnd());

            var echo = exchanges.First(e => e.PathAndQuery == "/echo");
            T.Eq("captured request body", "payload-42", Encoding.UTF8.GetString(echo.RequestBody));

            var noContent = exchanges.First(e => e.PathAndQuery == "/204");
            T.Eq("204 captured with empty body", 0, noContent.ResponseBody.Length);

            var head = exchanges.First(e => e.Method == "HEAD");
            T.Eq("HEAD captured with empty body", 0, head.ResponseBody.Length);

            T.Check("no capture has a null body array",
                exchanges.All(e => e.RequestBody is not null && e.ResponseBody is not null));

            var dead = exchanges.FirstOrDefault(e => e.PathAndQuery == "/dead");
            T.Check("unreachable upstream recorded as a failed exchange",
                dead is { State: ExchangeState.Failed, Error: not null }, dead?.State.ToString() ?? "no exchange recorded");
            T.Check("failed exchange still has a duration", dead?.Duration is not null);
        }

        try { Directory.Delete(caDir, true); } catch { }
    }
}

/// <summary>A tiny HTTP/1.1 origin server that writes exact, canned wire bytes so framing can be asserted.</summary>
public sealed class RawHttpServer
{
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public int Start()
    {
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptAsync(_cts.Token);
        return port;
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

    private static async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            var stream = client.GetStream();
            while (!ct.IsCancellationRequested)
            {
                var head = new StringBuilder();
                var one = new byte[1];
                while (!head.ToString().EndsWith("\r\n\r\n"))
                {
                    int n = await stream.ReadAsync(one, ct);
                    if (n == 0) return;
                    head.Append((char)one[0]);
                }

                string[] lines = head.ToString().Split("\r\n");
                string[] requestLine = lines[0].Split(' ');
                string method = requestLine[0];
                string path = requestLine.Length > 1 ? requestLine[1] : "/";

                int contentLength = 0;
                foreach (var line in lines)
                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                        contentLength = int.Parse(line[15..].Trim());

                var body = new byte[contentLength];
                int read = 0;
                while (read < contentLength)
                {
                    int n = await stream.ReadAsync(body.AsMemory(read), ct);
                    if (n == 0) return;
                    read += n;
                }

                await stream.WriteAsync(Respond(method, path, body), ct);
            }
        }
    }

    private static byte[] Respond(string method, string path, byte[] body)
    {
        if (method == "HEAD")
            return Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n");

        switch (path)
        {
            case "/len":
                return Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nhello-len");

            case "/chunked":
                return Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" +
                    "3\r\nabc\r\n5\r\ndefgh\r\n0\r\n\r\n");

            case "/gzip":
            {
                using var ms = new MemoryStream();
                using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
                    gz.Write(Encoding.ASCII.GetBytes("gzip-payload-0123456789"));
                byte[] compressed = ms.ToArray();
                var header = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: " +
                    compressed.Length + "\r\n\r\n");
                return [.. header, .. compressed];
            }

            case "/204":
                return Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\n\r\n");

            case "/echo":
            {
                var header = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + body.Length + "\r\n\r\n");
                return [.. header, .. body];
            }

            default:
                return Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        }
    }
}
