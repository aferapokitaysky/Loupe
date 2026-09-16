using System.Globalization;
using System.Text;

namespace Loupe.Proxy.Http;

public readonly record struct CaptureResult(byte[] CapturedBytes, bool Truncated);

/// <summary>
/// Copies an HTTP message body from one side of the proxy to the other,
/// byte-for-byte (so wire framing like chunk boundaries survives untouched),
/// while also siphoning off up to <c>captureLimit</c> bytes of the actual
/// payload for the UI to display later.
/// </summary>
public static class BodyRelay
{
    private const int BufferSize = 81920;

    public static async Task<CaptureResult> CopyContentLengthAsync(
        HttpLineReader source, Stream destination, long length, long captureLimit, CancellationToken ct)
    {
        var capture = new MemoryStream();
        var buffer = new byte[BufferSize];
        long remaining = length;

        while (remaining > 0)
        {
            int toRead = (int)Math.Min(buffer.Length, remaining);
            int read = await source.ReadAsync(buffer.AsMemory(0, toRead), ct).ConfigureAwait(false);
            if (read == 0) break; // peer closed early; forward what we saw and stop

            await destination.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            AppendCapture(capture, buffer, read, captureLimit);
            remaining -= read;
        }

        return new CaptureResult(capture.ToArray(), length > captureLimit);
    }

    public static async Task<CaptureResult> CopyChunkedAsync(
        HttpLineReader source, Stream destination, long captureLimit, CancellationToken ct)
    {
        var capture = new MemoryStream();
        var buffer = new byte[BufferSize];

        while (true)
        {
            string? sizeLine = await source.ReadLineAsync(ct).ConfigureAwait(false);
            if (sizeLine is null) break; // connection dropped mid-body
            await WriteLineAsync(destination, sizeLine, ct).ConfigureAwait(false);

            string sizeText = sizeLine.Split(';', 2)[0].Trim();
            if (!int.TryParse(sizeText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int chunkSize))
                break; // malformed chunk size - bail rather than loop forever

            if (chunkSize == 0)
            {
                // Trailer headers (usually none), terminated by a blank line.
                while (true)
                {
                    string? trailer = await source.ReadLineAsync(ct).ConfigureAwait(false);
                    if (trailer is null) break;
                    await WriteLineAsync(destination, trailer, ct).ConfigureAwait(false);
                    if (trailer.Length == 0) break;
                }
                break;
            }

            int remaining = chunkSize;
            while (remaining > 0)
            {
                int toRead = Math.Min(buffer.Length, remaining);
                int read = await source.ReadAsync(buffer.AsMemory(0, toRead), ct).ConfigureAwait(false);
                if (read == 0) { remaining = 0; break; }

                await destination.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                AppendCapture(capture, buffer, read, captureLimit);
                remaining -= read;
            }

            string? terminator = await source.ReadLineAsync(ct).ConfigureAwait(false);
            await WriteLineAsync(destination, terminator ?? "", ct).ConfigureAwait(false);
        }

        return new CaptureResult(capture.ToArray(), capture.Length >= captureLimit);
    }

    public static async Task<CaptureResult> CopyUntilCloseAsync(
        HttpLineReader source, Stream destination, long captureLimit, CancellationToken ct)
    {
        var capture = new MemoryStream();
        var buffer = new byte[BufferSize];

        while (true)
        {
            int read = await source.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0) break;

            await destination.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            AppendCapture(capture, buffer, read, captureLimit);
        }

        return new CaptureResult(capture.ToArray(), capture.Length >= captureLimit);
    }

    private static void AppendCapture(MemoryStream capture, byte[] buffer, int read, long captureLimit)
    {
        if (capture.Length >= captureLimit) return;
        int toCapture = (int)Math.Min(read, captureLimit - capture.Length);
        capture.Write(buffer, 0, toCapture);
    }

    private static Task WriteLineAsync(Stream destination, string line, CancellationToken ct)
    {
        byte[] bytes = Encoding.Latin1.GetBytes(line + "\r\n");
        return destination.WriteAsync(bytes, ct).AsTask();
    }
}
