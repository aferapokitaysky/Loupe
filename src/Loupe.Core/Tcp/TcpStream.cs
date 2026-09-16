namespace Loupe.Core.Tcp;

/// <summary>Reassembled byte stream for one direction of a TCP connection.</summary>
public sealed class TcpDirectionBuffer
{
    /// <summary>
    /// How much out-of-order data to hold while waiting for a gap to be filled. A segment
    /// that never arrives (dropped upstream, or capture started mid-stream) would otherwise
    /// pin every later segment in memory for the lifetime of the capture.
    /// </summary>
    private const int MaxPendingBytes = 2 * 1024 * 1024;

    private readonly Dictionary<uint, byte[]> _pendingBySeq = [];
    private int _pendingBytes;
    private uint? _nextExpectedSeq;
    private readonly MemoryStream _reassembled = new();

    public long TotalBytes => _reassembled.Length;

    /// <summary>Contiguous, in-order bytes reassembled so far (may lag behind live capture if segments are missing).</summary>
    public byte[] GetReassembledBytes() => _reassembled.ToArray();

    public void MarkStreamStart(uint isn) => _nextExpectedSeq ??= isn;

    public void AddSegment(uint seq, ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0) return;

        _nextExpectedSeq ??= seq; // first segment observed for this direction: assume in-order start

        if (SequenceLessThan(seq, _nextExpectedSeq.Value))
        {
            // Fully or partially retransmitted/overlapping data - keep only the new tail, if any.
            uint overlap = _nextExpectedSeq.Value - seq;
            if (overlap >= payload.Length) return;
            payload = payload[(int)overlap..];
            seq = _nextExpectedSeq.Value;
        }

        if (seq == _nextExpectedSeq.Value)
        {
            _reassembled.Write(payload);
            _nextExpectedSeq = seq + (uint)payload.Length;
            DrainPending();
        }
        else
        {
            if (!_pendingBySeq.TryGetValue(seq, out var existing))
            {
                if (_pendingBytes >= MaxPendingBytes)
                {
                    // The gap is never going to be filled - drop what we were holding for it
                    // rather than growing without bound. Bytes already reassembled are kept.
                    _pendingBySeq.Clear();
                    _pendingBytes = 0;
                }
                _pendingBytes += payload.Length;
            }
            else
            {
                _pendingBytes += payload.Length - existing.Length;
            }

            _pendingBySeq[seq] = payload.ToArray();
        }
    }

    private void DrainPending()
    {
        // Look the next sequence number up directly. Picking the numerically smallest
        // pending key instead would stall whenever a lower key is buffered that isn't the
        // one we need - which is exactly what happens every time the 32-bit sequence
        // number wraps past zero mid-stream.
        while (_pendingBySeq.TryGetValue(_nextExpectedSeq!.Value, out var next))
        {
            _reassembled.Write(next);
            _pendingBySeq.Remove(_nextExpectedSeq.Value);
            _pendingBytes -= next.Length;
            _nextExpectedSeq += (uint)next.Length;
        }
    }

    // TCP sequence numbers wrap around; compare using serial-number arithmetic (RFC 1982).
    private static bool SequenceLessThan(uint a, uint b) => unchecked(a - b) > 0x8000_0000;
}

public sealed class TcpStream
{
    public required TcpStreamKey Key { get; init; }
    public TcpDirectionBuffer AToB { get; } = new();
    public TcpDirectionBuffer BToA { get; } = new();
    public DateTimeOffset LastActivity { get; set; }
}
