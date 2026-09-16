using System.Text;

namespace Loupe.Proxy.Http;

/// <summary>
/// Reads CRLF-terminated HTTP header lines off a stream with a small internal
/// buffer, while still allowing exact byte-for-byte reads of whatever body
/// follows (via <see cref="ReadAsync"/>) without losing bytes that were
/// already buffered past the end of the headers.
/// </summary>
public sealed class HttpLineReader(Stream inner)
{
    private readonly byte[] _buffer = new byte[8192];
    private int _length;
    private int _position;

    /// <summary>Reads one line (headers section), stripping the trailing CRLF/LF. Null on a clean EOF at a line boundary.</summary>
    public async Task<string?> ReadLineAsync(CancellationToken ct = default)
    {
        using var line = new MemoryStream();
        bool sawAnyByte = false;

        while (true)
        {
            if (_position >= _length)
            {
                _length = await inner.ReadAsync(_buffer, ct).ConfigureAwait(false);
                _position = 0;
                if (_length == 0)
                    return sawAnyByte ? Encoding.Latin1.GetString(line.ToArray()) : null;
            }

            byte b = _buffer[_position++];
            sawAnyByte = true;

            if (b == '\n')
            {
                var bytes = line.ToArray();
                int trim = bytes.Length > 0 && bytes[^1] == '\r' ? 1 : 0;
                return Encoding.Latin1.GetString(bytes, 0, bytes.Length - trim);
            }

            line.WriteByte(b);
        }
    }

    /// <summary>Reads up to <paramref name="count"/> bytes of raw body, preferring already-buffered bytes first.</summary>
    public async Task<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_position < _length)
        {
            int fromBuffer = Math.Min(buffer.Length, _length - _position);
            _buffer.AsSpan(_position, fromBuffer).CopyTo(buffer.Span);
            _position += fromBuffer;
            return fromBuffer;
        }

        return await inner.ReadAsync(buffer, ct).ConfigureAwait(false);
    }
}
