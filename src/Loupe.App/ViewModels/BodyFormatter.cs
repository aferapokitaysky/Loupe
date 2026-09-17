using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Loupe.App.Localization;
using Loupe.Core.Util;
using Loupe.Proxy.Http;

namespace Loupe.App.ViewModels;

/// <summary>Turns a captured HTTP body into something readable: decompresses, pretty-prints JSON, falls back to a hex dump for binary data.</summary>
public static class BodyFormatter
{
    public static string Format(IReadOnlyList<HttpHeader> headers, byte[] body, bool truncated)
    {
        if (body.Length == 0) return Loc.Get("Body_Empty");

        byte[] decoded = Decompress(body, headers.Get("Content-Encoding"));
        string contentType = headers.Get("Content-Type") ?? "";

        string text = TryFormatAsText(decoded, contentType) ?? HexDump.Format(decoded);
        return truncated ? text + Loc.Get("Body_Truncated") : text;
    }

    /// <summary>
    /// The body as the server meant it: the captured bytes with any `Content-Encoding` undone.
    /// This is what gets written to disk when a response is saved - nobody wants a file that is
    /// named `.json` and holds gzip.
    /// </summary>
    public static byte[] Decode(IReadOnlyList<HttpHeader> headers, byte[] body) =>
        Decompress(body, headers.Get("Content-Encoding"));

    /// <summary>True for bodies worth searching or showing as text, by their declared type.</summary>
    public static bool LooksTextual(string? contentType) =>
        contentType is null
        || contentType.Length == 0
        || contentType.Contains("json", StringComparison.OrdinalIgnoreCase)
        || contentType.Contains("text", StringComparison.OrdinalIgnoreCase)
        || contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)
        || contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase)
        || contentType.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);

    private static byte[] Decompress(byte[] body, string? contentEncoding)
    {
        if (string.IsNullOrEmpty(contentEncoding)) return body;

        try
        {
            using var input = new MemoryStream(body);
            using var output = new MemoryStream();
            Stream? decompressor = contentEncoding.Trim().ToLowerInvariant() switch
            {
                "gzip" => new GZipStream(input, CompressionMode.Decompress),
                "deflate" => new DeflateStream(input, CompressionMode.Decompress),
                "br" => new BrotliStream(input, CompressionMode.Decompress),
                _ => null,
            };
            if (decompressor is null) return body;

            using (decompressor)
                decompressor.CopyTo(output);
            return output.ToArray();
        }
        catch
        {
            return body; // truncated capture or unsupported encoding - show raw bytes instead of failing
        }
    }

    private static string? TryFormatAsText(byte[] data, string contentType)
    {
        if (!LooksTextual(contentType)) return null;

        string text;
        try { text = Encoding.UTF8.GetString(data); }
        catch { return null; }

        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase) || LooksLikeJson(text))
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
            }
            catch { /* not actually valid JSON - fall through to raw text */ }
        }

        return text;
    }

    private static bool LooksLikeJson(string text)
    {
        string trimmed = text.TrimStart();
        return trimmed.StartsWith('{') || trimmed.StartsWith('[');
    }
}
