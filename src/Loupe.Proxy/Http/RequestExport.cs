using System.Text;
using System.Text.Json;

namespace Loupe.Proxy.Http;

/// <summary>
/// Turns a captured request back into something you can paste somewhere else - a curl
/// command, a PowerShell call, a fetch() snippet. This is how a request found in the
/// proxy gets reproduced in a terminal, a script or a browser console.
///
/// Hop-by-hop headers are left out: they describe the connection the request arrived on,
/// not the request, and pasting them back produces a broken or misleading call.
/// </summary>
public static class RequestExport
{
    private static readonly HashSet<string> SkippedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        // Connection-scoped (RFC 9110 §7.6.1) plus the ones every client recomputes for itself.
        "Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding",
        "Upgrade", "Content-Length", "Host",
    };

    public static string ToCurl(HttpExchange exchange)
    {
        var lines = new List<string>();
        string method = exchange.Method.ToUpperInvariant();

        // curl sends GET by default and infers POST from --data; spelling it out anyway keeps
        // the command readable when it is pasted into a ticket.
        lines.Add(method == "GET"
            ? $"curl {Quote(exchange.Url)}"
            : $"curl -X {method} {Quote(exchange.Url)}");

        foreach (var header in Headers(exchange))
            lines.Add($"  -H {Quote($"{header.Name}: {header.Value}")}");

        if (BodyText(exchange) is { } body)
            lines.Add($"  --data-raw {Quote(body)}");
        else if (exchange.RequestBody.Length > 0)
            lines.Add($"  # {exchange.RequestBody.Length} bytes of binary body omitted");

        return string.Join(" \\\n", lines);

        // Single quotes take everything literally in a POSIX shell; the one thing they cannot
        // hold is a single quote, which has to leave and re-enter the quoting.
        static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";
    }

    public static string ToPowerShell(HttpExchange exchange)
    {
        var builder = new StringBuilder();
        var headers = Headers(exchange)
            // Invoke-WebRequest refuses Content-Type in -Headers and takes it as its own
            // parameter instead.
            .Where(h => !string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (headers.Count > 0)
        {
            builder.AppendLine("$headers = @{");
            foreach (var header in headers)
                builder.AppendLine($"    {Quote(header.Name)} = {Quote(header.Value)}");
            builder.AppendLine("}");
        }

        builder.Append($"Invoke-WebRequest -Uri {Quote(exchange.Url)} -Method {exchange.Method.ToUpperInvariant()}");
        if (headers.Count > 0) builder.Append(" -Headers $headers");

        if (exchange.RequestHeaders.Get("Content-Type") is { Length: > 0 } contentType)
            builder.Append($" -ContentType {Quote(contentType)}");

        if (BodyText(exchange) is { } body)
            builder.Append($" -Body {Quote(body)}");
        else if (exchange.RequestBody.Length > 0)
            builder.Append($"   # {exchange.RequestBody.Length} bytes of binary body omitted");

        return builder.ToString();

        // PowerShell's literal string: a single quote doubles itself, nothing else is special.
        static string Quote(string value) => "'" + value.Replace("'", "''") + "'";
    }

    public static string ToFetch(HttpExchange exchange)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"await fetch({Json(exchange.Url)}, {{");
        builder.AppendLine($"  method: {Json(exchange.Method.ToUpperInvariant())},");

        var headers = Headers(exchange).ToList();
        if (headers.Count > 0)
        {
            builder.AppendLine("  headers: {");
            for (int i = 0; i < headers.Count; i++)
                builder.AppendLine($"    {Json(headers[i].Name)}: {Json(headers[i].Value)}{(i < headers.Count - 1 ? "," : "")}");
            builder.AppendLine("  },");
        }

        if (BodyText(exchange) is { } body)
            builder.AppendLine($"  body: {Json(body)},");
        else if (exchange.RequestBody.Length > 0)
            builder.AppendLine($"  // {exchange.RequestBody.Length} bytes of binary body omitted");

        builder.Append("});");
        return builder.ToString();

        // JSON string literals are valid JavaScript ones, escaping included.
        static string Json(string value) => JsonSerializer.Serialize(value, JsSnippet);
    }

    /// <summary>
    /// The relaxed encoder, because this text is read by a person before it is run by anything:
    /// the default one turns every quote and apostrophe in a JSON body into " and ',
    /// which makes a pasted snippet unreadable. Nothing here is written into a web page, where
    /// that escaping is what protects you.
    /// </summary>
    private static readonly JsonSerializerOptions JsSnippet = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static IEnumerable<HttpHeader> Headers(HttpExchange exchange) =>
        exchange.RequestHeaders.Where(h => !SkippedHeaders.Contains(h.Name));

    /// <summary>
    /// The body as text when it is text, else null. A JPEG pasted into a shell command is
    /// noise at best and a broken command at worst, so binary bodies are described instead.
    /// </summary>
    private static string? BodyText(HttpExchange exchange)
    {
        if (exchange.RequestBody.Length == 0) return null;

        try
        {
            string text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(exchange.RequestBody);
            return text.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t')) ? null : text;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }
}
