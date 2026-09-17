using System.Text;
using Loupe.Proxy.Http;

/// <summary>
/// Covers the two things you can do with a captured request afterwards: paste it somewhere
/// else (<see cref="RequestExport"/>) or send it again (<see cref="RequestReplayer"/>).
/// </summary>
public static class ReplayTests
{
    public static async Task RunAsync()
    {
        T.Section("REQUEST EXPORT");
        {
            var exchange = Sample("POST", "/v1/items?q=a b", [
                new("Host", "api.example.com"),
                new("Content-Type", "application/json"),
                new("Accept", "application/json"),
                new("Content-Length", "13"),
                new("Connection", "keep-alive"),
            ], """{"it's":1}""");

            string curl = RequestExport.ToCurl(exchange);
            T.Check("curl names the method", curl.StartsWith("curl -X POST "), curl.Split('\n')[0]);
            T.Check("curl quotes the URL", curl.Contains("'https://api.example.com/v1/items?q=a b'"));
            T.Check("curl carries the headers it should", curl.Contains("-H 'Accept: application/json'"));
            T.Check("curl drops hop-by-hop and recomputed headers",
                !curl.Contains("Connection:") && !curl.Contains("Content-Length:") && !curl.Contains("-H 'Host:"));
            T.Check("curl escapes a quote in the body", curl.Contains("""--data-raw '{"it'\''s":1}'"""), curl);

            var get = Sample("GET", "/plain", [new("Accept", "*/*")], "");
            T.Check("curl leaves -X off a plain GET", RequestExport.ToCurl(get).StartsWith("curl 'https://"));
            T.Check("curl has no body line for a bodyless request", !RequestExport.ToCurl(get).Contains("--data-raw"));

            string ps = RequestExport.ToPowerShell(exchange);
            T.Check("PowerShell builds a header table", ps.Contains("$headers = @{") && ps.Contains("'Accept' = 'application/json'"));
            T.Check("PowerShell passes Content-Type as its own parameter",
                ps.Contains("-ContentType 'application/json'") && !ps.Contains("'Content-Type' ="), ps);
            T.Check("PowerShell doubles a quote in the body", ps.Contains("""-Body '{"it''s":1}'"""), ps);

            string fetch = RequestExport.ToFetch(exchange);
            T.Check("fetch names the method", fetch.Contains("""method: "POST","""));
            T.Check("fetch escapes the body as a JS string", fetch.Contains("""body: "{\"it's\":1}","""), fetch);

            // A PNG pasted into a shell command is a broken command, not a body.
            var binary = new HttpExchange
            {
                Id = 9, StartTime = DateTimeOffset.Now, IsHttps = true, Host = "h", Port = 443,
                Method = "PUT", PathAndQuery = "/upload",
                RequestHeaders = [new("Content-Type", "image/png")],
                RequestBody = [0x89, 0x50, 0x4E, 0x47, 0x00, 0x01, 0x02],
            };
            T.Check("binary body is described, not pasted",
                RequestExport.ToCurl(binary).Contains("7 bytes of binary body omitted")
                && !RequestExport.ToCurl(binary).Contains("--data-raw"));
        }

        T.Section("REQUEST REPLAY (against the local HTTP server)");
        {
            var origin = new RawHttpServer();
            int port = origin.Start();
            using var replayer = new RequestReplayer(timeout: TimeSpan.FromSeconds(10));

            var captured = new HttpExchange
            {
                Id = 1, StartTime = DateTimeOffset.Now.AddMinutes(-5), IsHttps = false,
                Host = "127.0.0.1", Port = port,
                Client = new ClientApplication("tests", null),
                Method = "GET", PathAndQuery = "/len",
                RequestHeaders = [new("Accept", "*/*"), new("Connection", "keep-alive")],
                StatusCode = 200, State = ExchangeState.ResponseReceived,
            };

            var replay = await replayer.ReplayAsync(captured, id: -1);
            T.Eq("replayed GET gets the same status", 200, replay.StatusCode);
            T.Eq("replayed GET gets the same body", "hello-len", Encoding.UTF8.GetString(replay.ResponseBody));
            T.Check("replay is marked as one", replay.IsReplay);
            T.Eq("replay keeps the original's id it was given", -1L, replay.Id);
            T.Eq("replay keeps the sending app", "tests", replay.Client?.Name);
            T.Check("replay is timed", replay.Duration is not null);
            T.Check("replay keeps the request it sent", replay.Method == "GET" && replay.PathAndQuery == "/len");

            var post = new HttpExchange
            {
                Id = 2, StartTime = DateTimeOffset.Now, IsHttps = false, Host = "127.0.0.1", Port = port,
                Method = "POST", PathAndQuery = "/echo",
                RequestHeaders = [new("Content-Type", "text/plain"), new("Content-Length", "999")],
                RequestBody = Encoding.UTF8.GetBytes("replay-me"),
            };
            var echoed = await replayer.ReplayAsync(post, id: -2);
            T.Eq("replayed POST sends its body", "replay-me", Encoding.UTF8.GetString(echoed.ResponseBody));

            var withHeaders = new HttpExchange
            {
                Id = 3, StartTime = DateTimeOffset.Now, IsHttps = false, Host = "127.0.0.1", Port = port,
                Method = "GET", PathAndQuery = "/head",
                RequestHeaders = [new("X-Token", "abc123"), new("Connection", "close"), new("Host", "elsewhere.example")],
            };
            string head = Encoding.UTF8.GetString((await replayer.ReplayAsync(withHeaders, id: -3)).ResponseBody);
            T.Check("replay forwards the captured headers", head.Contains("X-Token: abc123"), head.Replace("\r\n", " | "));
            T.Check("replay sends the real Host, not the captured one",
                head.Contains("Host: 127.0.0.1:" + port) && !head.Contains("elsewhere.example"), head.Replace("\r\n", " | "));

            var dead = new HttpExchange
            {
                Id = 4, StartTime = DateTimeOffset.Now, IsHttps = false, Host = "127.0.0.1", Port = 9,
                Method = "GET", PathAndQuery = "/nothing-here",
            };
            var failed = await replayer.ReplayAsync(dead, id: -4);
            T.Check("unreachable replay fails instead of throwing",
                failed is { State: ExchangeState.Failed, Error: not null }, failed.State.ToString());

            origin.Stop();
        }
    }

    private static HttpExchange Sample(string method, string path, List<HttpHeader> headers, string body) => new()
    {
        Id = 1,
        StartTime = DateTimeOffset.Now,
        IsHttps = true,
        Host = "api.example.com",
        Port = 443,
        Method = method,
        PathAndQuery = path,
        RequestHeaders = headers,
        RequestBody = Encoding.UTF8.GetBytes(body),
    };
}
