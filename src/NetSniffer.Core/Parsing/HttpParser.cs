using System.Text;
using NetSniffer.Core.Model;

namespace NetSniffer.Core.Parsing;

/// <summary>Recognizes plaintext HTTP/1.x request/response lines. No TLS involved here.</summary>
public static class HttpParser
{
    private static readonly string[] Methods =
        ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "];

    public static bool TryParse(byte[] data, int offset, int length, ParsedPacket packet)
    {
        int previewLen = Math.Min(length, 512);
        string preview = Encoding.ASCII.GetString(data, offset, previewLen);

        bool isRequest = Methods.Any(m => preview.StartsWith(m, StringComparison.Ordinal));
        bool isResponse = preview.StartsWith("HTTP/", StringComparison.Ordinal);
        if (!isRequest && !isResponse) return false;

        int lineEnd = preview.IndexOf("\r\n", StringComparison.Ordinal);
        string firstLine = lineEnd >= 0 ? preview[..lineEnd] : preview;

        var layer = new PacketLayer { Name = "HTTP", Offset = offset, Length = length }
            .With(isRequest ? "Request Line" : "Status Line", firstLine, offset, firstLine.Length);

        string? host = ExtractHeader(preview, "Host");
        if (host != null) layer.With("Host", host, offset, 0);

        packet.Layers.Add(layer);
        packet.Protocol = "HTTP";
        packet.Info = host != null ? $"{firstLine} (Host: {host})" : firstLine;

        // A Host header names the destination the same way an SNI does. Strip any :port.
        if (host != null)
        {
            int colon = host.LastIndexOf(':');
            string bare = colon > 0 && !host.Contains(']') ? host[..colon] : host;
            packet.AddNameHint(packet.DestinationAddress, bare, NameHintSource.HttpHost);
        }
        return true;
    }

    private static string? ExtractHeader(string text, string headerName)
    {
        foreach (var line in text.Split("\r\n"))
        {
            int colon = line.IndexOf(':');
            if (colon > 0 && string.Equals(line[..colon], headerName, StringComparison.OrdinalIgnoreCase))
                return line[(colon + 1)..].Trim();
        }
        return null;
    }
}
