using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSniffer.Proxy.Http;

/// <summary>
/// Writes captured exchanges as HAR 1.2 (the HTTP Archive format).
///
/// This is the format other tools actually read - Proxyman, Charles, Fiddler, Chrome DevTools -
/// so an export here opens anywhere, rather than only in this app. Bodies come along: text as
/// text, anything else base64 with the encoding recorded, which is what the spec says.
/// </summary>
public static class HarFile
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static void Write(string path, IEnumerable<HttpExchange> exchanges, string creatorVersion = "1.0")
    {
        using var stream = File.Create(path);
        Write(stream, exchanges, creatorVersion);
    }

    public static void Write(Stream stream, IEnumerable<HttpExchange> exchanges, string creatorVersion = "1.0")
    {
        var log = new HarLog
        {
            Version = "1.2",
            Creator = new HarCreator { Name = "NetSniffer", Version = creatorVersion },
            Entries = [.. exchanges.Select(ToEntry)],
        };

        JsonSerializer.Serialize(stream, new HarRoot { Log = log }, Options);
    }

    private static HarEntry ToEntry(HttpExchange exchange)
    {
        double elapsed = exchange.Duration?.TotalMilliseconds ?? -1;

        return new HarEntry
        {
            StartedDateTime = exchange.StartTime.ToString("o"),
            Time = elapsed,
            // HAR has no field for "which app sent this", so it goes in the comment rather
            // than being dropped - readers show it, and the file stays valid.
            Comment = exchange.Client is { } client ? $"client: {client.Name}" : null,
            Request = new HarRequest
            {
                Method = exchange.Method,
                Url = exchange.Url,
                HttpVersion = Version(exchange.HttpVersion),
                Headers = [.. exchange.RequestHeaders.Select(h => new HarNameValue { Name = h.Name, Value = h.Value })],
                QueryString = [.. QueryPairs(exchange.PathAndQuery)],
                Cookies = [],
                HeadersSize = -1,
                BodySize = exchange.RequestBody.Length,
                PostData = exchange.RequestBody.Length == 0 ? null : new HarPostData
                {
                    MimeType = ContentType(exchange.RequestHeaders) ?? "application/octet-stream",
                    Text = AsText(exchange.RequestBody, exchange.RequestHeaders, out string? requestEncoding),
                    Encoding = requestEncoding,
                },
            },
            Response = new HarResponse
            {
                Status = exchange.StatusCode ?? 0,
                StatusText = exchange.ReasonPhrase ?? (exchange.Error is null ? "" : "Failed"),
                HttpVersion = Version(exchange.HttpVersion),
                Headers = [.. exchange.ResponseHeaders.Select(h => new HarNameValue { Name = h.Name, Value = h.Value })],
                Cookies = [],
                HeadersSize = -1,
                BodySize = exchange.ResponseBody.Length,
                RedirectUrl = exchange.ResponseHeaders
                    .FirstOrDefault(h => string.Equals(h.Name, "Location", StringComparison.OrdinalIgnoreCase)).Value ?? "",
                Content = new HarContent
                {
                    Size = exchange.ResponseBody.Length,
                    MimeType = ContentType(exchange.ResponseHeaders) ?? "",
                    Text = exchange.ResponseBody.Length == 0
                        ? null
                        : AsText(exchange.ResponseBody, exchange.ResponseHeaders, out string? responseEncoding),
                    Encoding = exchange.ResponseBody.Length == 0 ? null : ResponseEncoding(exchange),
                },
            },
            Cache = new HarCache(),
            Timings = new HarTimings { Send = 0, Wait = elapsed < 0 ? -1 : elapsed, Receive = 0 },
        };
    }

    /// <summary>Recomputed rather than captured from the out parameter above, which the object
    /// initialiser can't reach.</summary>
    private static string? ResponseEncoding(HttpExchange exchange) =>
        IsTextual(ContentType(exchange.ResponseHeaders)) && IsValidUtf8(exchange.ResponseBody) ? null : "base64";

    private static string AsText(byte[] body, List<HttpHeader> headers, out string? encoding)
    {
        if (IsTextual(ContentType(headers)) && IsValidUtf8(body))
        {
            encoding = null;
            return Encoding.UTF8.GetString(body);
        }

        encoding = "base64";
        return Convert.ToBase64String(body);
    }

    private static bool IsTextual(string? contentType)
    {
        if (contentType is null) return false;

        string type = contentType.Split(';')[0].Trim().ToLowerInvariant();
        return type.StartsWith("text/")
               || type is "application/json" or "application/javascript" or "application/xml"
                          or "application/x-www-form-urlencoded" or "application/graphql"
               || type.EndsWith("+json") || type.EndsWith("+xml");
    }

    /// <summary>A "text" body that isn't valid UTF-8 would come back mangled, so it goes as base64.</summary>
    private static bool IsValidUtf8(byte[] body)
    {
        try
        {
            new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(body);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static string? ContentType(List<HttpHeader> headers) =>
        headers.Where(h => string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase))
               .Select(h => h.Value)
               .FirstOrDefault();

    private static string Version(string httpVersion) =>
        string.IsNullOrWhiteSpace(httpVersion) ? "HTTP/1.1" : httpVersion;

    private static IEnumerable<HarNameValue> QueryPairs(string pathAndQuery)
    {
        int question = pathAndQuery.IndexOf('?');
        if (question < 0 || question == pathAndQuery.Length - 1) yield break;

        foreach (string pair in pathAndQuery[(question + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int equals = pair.IndexOf('=');
            yield return equals < 0
                ? new HarNameValue { Name = Uri.UnescapeDataString(pair), Value = "" }
                : new HarNameValue
                {
                    Name = Uri.UnescapeDataString(pair[..equals]),
                    Value = Uri.UnescapeDataString(pair[(equals + 1)..]),
                };
        }
    }

    // ---- HAR 1.2 shape. Property names are lower camel case, as the spec requires.

    private sealed class HarRoot { [JsonPropertyName("log")] public HarLog Log { get; set; } = new(); }

    private sealed class HarLog
    {
        [JsonPropertyName("version")] public string Version { get; set; } = "1.2";
        [JsonPropertyName("creator")] public HarCreator Creator { get; set; } = new();
        [JsonPropertyName("entries")] public List<HarEntry> Entries { get; set; } = [];
    }

    private sealed class HarCreator
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("version")] public string Version { get; set; } = "";
    }

    private sealed class HarEntry
    {
        [JsonPropertyName("startedDateTime")] public string StartedDateTime { get; set; } = "";
        [JsonPropertyName("time")] public double Time { get; set; }
        [JsonPropertyName("request")] public HarRequest Request { get; set; } = new();
        [JsonPropertyName("response")] public HarResponse Response { get; set; } = new();
        [JsonPropertyName("cache")] public HarCache Cache { get; set; } = new();
        [JsonPropertyName("timings")] public HarTimings Timings { get; set; } = new();
        [JsonPropertyName("comment")] public string? Comment { get; set; }
    }

    private sealed class HarRequest
    {
        [JsonPropertyName("method")] public string Method { get; set; } = "";
        [JsonPropertyName("url")] public string Url { get; set; } = "";
        [JsonPropertyName("httpVersion")] public string HttpVersion { get; set; } = "";
        [JsonPropertyName("headers")] public List<HarNameValue> Headers { get; set; } = [];
        [JsonPropertyName("queryString")] public List<HarNameValue> QueryString { get; set; } = [];
        [JsonPropertyName("cookies")] public List<HarNameValue> Cookies { get; set; } = [];
        [JsonPropertyName("headersSize")] public int HeadersSize { get; set; } = -1;
        [JsonPropertyName("bodySize")] public int BodySize { get; set; }
        [JsonPropertyName("postData")] public HarPostData? PostData { get; set; }
    }

    private sealed class HarPostData
    {
        [JsonPropertyName("mimeType")] public string MimeType { get; set; } = "";
        [JsonPropertyName("text")] public string Text { get; set; } = "";
        [JsonPropertyName("encoding")] public string? Encoding { get; set; }
    }

    private sealed class HarResponse
    {
        [JsonPropertyName("status")] public int Status { get; set; }
        [JsonPropertyName("statusText")] public string StatusText { get; set; } = "";
        [JsonPropertyName("httpVersion")] public string HttpVersion { get; set; } = "";
        [JsonPropertyName("headers")] public List<HarNameValue> Headers { get; set; } = [];
        [JsonPropertyName("cookies")] public List<HarNameValue> Cookies { get; set; } = [];
        [JsonPropertyName("content")] public HarContent Content { get; set; } = new();
        [JsonPropertyName("redirectURL")] public string RedirectUrl { get; set; } = "";
        [JsonPropertyName("headersSize")] public int HeadersSize { get; set; } = -1;
        [JsonPropertyName("bodySize")] public int BodySize { get; set; }
    }

    private sealed class HarContent
    {
        [JsonPropertyName("size")] public int Size { get; set; }
        [JsonPropertyName("mimeType")] public string MimeType { get; set; } = "";
        [JsonPropertyName("text")] public string? Text { get; set; }
        [JsonPropertyName("encoding")] public string? Encoding { get; set; }
    }

    private sealed class HarCache { }

    private sealed class HarTimings
    {
        [JsonPropertyName("send")] public double Send { get; set; }
        [JsonPropertyName("wait")] public double Wait { get; set; }
        [JsonPropertyName("receive")] public double Receive { get; set; }
    }

    private sealed class HarNameValue
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("value")] public string Value { get; set; } = "";
    }
}
