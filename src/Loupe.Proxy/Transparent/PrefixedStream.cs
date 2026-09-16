namespace Loupe.Proxy.Transparent;

/// <summary>
/// Replays bytes that were already read from a stream, then continues with the stream itself.
///
/// Transparent mode has to read the start of the connection to find out where it is going
/// (the SNI, or the Host header), but TLS and HTTP both then need those very same bytes. A
/// socket cannot be rewound, so the peeked prefix is put back in front here.
/// </summary>
public sealed class PrefixedStream(byte[] prefix, Stream inner) : Stream
{
    private readonly byte[] _prefix = prefix;
    private int _prefixPosition;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        // Never mix prefix and live bytes in one read: callers are entitled to a short read,
        // and keeping the two apart keeps the boundary trivially correct.
        int remaining = _prefix.Length - _prefixPosition;
        if (remaining <= 0) return inner.Read(buffer);

        int take = Math.Min(remaining, buffer.Length);
        _prefix.AsSpan(_prefixPosition, take).CopyTo(buffer);
        _prefixPosition += take;
        return take;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int remaining = _prefix.Length - _prefixPosition;
        if (remaining <= 0) return await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

        int take = Math.Min(remaining, buffer.Length);
        _prefix.AsMemory(_prefixPosition, take).CopyTo(buffer);
        _prefixPosition += take;
        return take;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    public override void Write(ReadOnlySpan<byte> buffer) => inner.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        inner.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) inner.Dispose();
        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync() => inner.DisposeAsync();
}
