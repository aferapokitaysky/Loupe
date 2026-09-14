namespace NetSniffer.Core.Tcp;

/// <summary>Reassembled byte stream for one direction of a TCP connection.</summary>
public sealed class TcpDirectionBuffer
{
    private readonly SortedDictionary<uint, byte[]> _pendingBySeq = new();
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
            _pendingBySeq[seq] = payload.ToArray();
        }
    }

    private void DrainPending()
    {
        while (_pendingBySeq.Count > 0)
        {
            var first = _pendingBySeq.First();
            if (first.Key != _nextExpectedSeq!.Value) break;

            _reassembled.Write(first.Value);
            _nextExpectedSeq = first.Key + (uint)first.Value.Length;
            _pendingBySeq.Remove(first.Key);
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
