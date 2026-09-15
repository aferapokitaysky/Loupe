using System.Text;
using System.Text.Json;
using NetSniffer.Proxy.Http;

/// <summary>
/// HAR export: the file has to be readable by other tools, so it is checked against the shape
/// the 1.2 spec describes rather than against our own reader.
/// </summary>
public static class HarTests
{
    public static void Run()
    {
        T.Section("HAR EXPORT");

        var exchanges = new List<HttpExchange>
        {
            new()
            {
                Id = 1,
                StartTime = new DateTimeOffset(2026, 9, 16, 2, 30, 0, TimeSpan.FromHours(3)),
                IsHttps = true,
                Host = "api.example.com",
                Port = 443,
                Method = "POST",
                PathAndQuery = "/v1/search?q=hello%20world&limit=10&debug",
                HttpVersion = "HTTP/1.1",
                StatusCode = 200,
                ReasonPhrase = "OK",
                State = ExchangeState.ResponseReceived,
                Duration = TimeSpan.FromMilliseconds(137),
                Client = new ClientApplication("chrome", @"C:\chrome.exe"),
                RequestHeaders = [new HttpHeader("Content-Type", "application/json"), new HttpHeader("Accept", "*/*")],
                RequestBody = Encoding.UTF8.GetBytes("""{"q":"hello"}"""),
                ResponseHeaders = [new HttpHeader("Content-Type", "application/json; charset=utf-8")],
                ResponseBody = Encoding.UTF8.GetBytes("""{"ok":true,"текст":"да"}"""),
            },
            new()
            {
                Id = 2,
                StartTime = new DateTimeOffset(2026, 9, 16, 2, 30, 1, TimeSpan.FromHours(3)),
                IsHttps = false,
                Host = "cdn.example.com",
                Port = 80,
                Method = "GET",
                PathAndQuery = "/logo.png",
                HttpVersion = "HTTP/1.1",
                StatusCode = 200,
                ReasonPhrase = "OK",
                State = ExchangeState.ResponseReceived,
                ResponseHeaders = [new HttpHeader("Content-Type", "image/png")],
                ResponseBody = [0x89, 0x50, 0x4E, 0x47, 0xFF, 0xFE], // not valid UTF-8 on purpose
            },
            new()
            {
                Id = 3,
                StartTime = DateTimeOffset.Now,
                IsHttps = true,
                Host = "dead.example.com",
                Port = 443,
                Method = "GET",
                PathAndQuery = "/",
                HttpVersion = "HTTP/1.1",
                State = ExchangeState.Failed,
                Error = "connection refused",
            },
        };

        string path = Path.Combine(Path.GetTempPath(), $"ns-har-{Guid.NewGuid():N}.har");
        HarFile.Write(path, exchanges, creatorVersion: "0.7.0");

        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var log = document.RootElement.GetProperty("log");

        T.Eq("HAR version", "1.2", log.GetProperty("version").GetString());
        T.Eq("creator named", "NetSniffer", log.GetProperty("creator").GetProperty("name").GetString());
        T.Eq("every exchange became an entry", 3, log.GetProperty("entries").GetArrayLength());

        var first = log.GetProperty("entries")[0];
        var request = first.GetProperty("request");
        var response = first.GetProperty("response");

        T.Eq("absolute URL, scheme and all", "https://api.example.com/v1/search?q=hello%20world&limit=10&debug",
            request.GetProperty("url").GetString());
        T.Eq("method", "POST", request.GetProperty("method").GetString());
        T.Eq("startedDateTime is ISO 8601", "2026-09-16T02:30:00.0000000+03:00",
            first.GetProperty("startedDateTime").GetString());
        T.Eq("time in milliseconds", 137d, first.GetProperty("time").GetDouble());

        var query = request.GetProperty("queryString");
        T.Eq("query string parsed out", 3, query.GetArrayLength());
        T.Eq("query values are decoded", "hello world", query[0].GetProperty("value").GetString());
        T.Eq("a valueless query key still appears", "debug", query[2].GetProperty("name").GetString());

        T.Eq("request headers carried", 2, request.GetProperty("headers").GetArrayLength());
        T.Eq("request body kept as text", """{"q":"hello"}""",
            request.GetProperty("postData").GetProperty("text").GetString());

        T.Eq("status", 200, response.GetProperty("status").GetInt32());
        T.Eq("JSON response stays readable text", """{"ok":true,"текст":"да"}""",
            response.GetProperty("content").GetProperty("text").GetString());
        T.Check("text content has no base64 marker",
            !response.GetProperty("content").TryGetProperty("encoding", out _));
        T.Eq("content size is the byte length, not the character count",
            Encoding.UTF8.GetByteCount("""{"ok":true,"текст":"да"}"""),
            response.GetProperty("content").GetProperty("size").GetInt32());

        T.Check("client app recorded in the comment",
            first.GetProperty("comment").GetString()!.Contains("chrome"));

        var binary = log.GetProperty("entries")[1].GetProperty("response").GetProperty("content");
        T.Eq("binary body is base64", "base64", binary.GetProperty("encoding").GetString());
        T.Check("and decodes back to the original bytes",
            Convert.FromBase64String(binary.GetProperty("text").GetString()!)
                   .SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0xFF, 0xFE }));

        var failed = log.GetProperty("entries")[2];
        T.Eq("a failed exchange still exports", 0, failed.GetProperty("response").GetProperty("status").GetInt32());
        T.Eq("with -1 for unknown time", -1d, failed.GetProperty("time").GetDouble());

        T.Check("every entry has the required members",
            log.GetProperty("entries").EnumerateArray().All(e =>
                e.TryGetProperty("request", out _) && e.TryGetProperty("response", out _)
                && e.TryGetProperty("cache", out _) && e.TryGetProperty("timings", out _)));

        File.Delete(path);
    }
}
