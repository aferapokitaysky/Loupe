using System.Text;

namespace Loupe.Core.Util;

/// <summary>Reassembled bytes as something a person can read in a pane.</summary>
public static class StreamText
{
    /// <summary>
    /// Decodes as UTF-8 and replaces unprintable characters with dots, the convention every
    /// packet tool uses. Without it a TLS record dropped into a text box scrolls the pane
    /// sideways with escape sequences, eats following text as control codes and can ring the
    /// terminal bell - and none of that is what the bytes mean.
    ///
    /// Tabs and line breaks are kept: they are what makes an HTTP exchange readable.
    /// </summary>
    public static string Readable(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return "";

        // Invalid sequences become U+FFFD rather than throwing: a stream cut mid-character
        // (the capture stopped, a segment is missing) is normal, not an error.
        string text = Encoding.UTF8.GetString(data);

        var builder = new StringBuilder(text.Length);
        foreach (char c in text)
            builder.Append(char.IsControl(c) && c is not ('\r' or '\n' or '\t') ? '.' : c);

        return builder.ToString();
    }
}
