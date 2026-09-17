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

    /// <summary>
    /// Segments arrive on the capture's parsing thread while "follow this stream" reads from the
    /// UI thread. MemoryStream is not safe for that on its own: a read taken mid-write returns a
    /// torn buffer, or throws.
    /// </summary>
    private readonly object _gate = new();

    public long TotalBytes
    {
        get { lock (_gate) return _reassembled.Length; }
    }

    /// <summary>Contiguous, in-order bytes reassembled so far (may lag behind live capture if segments are missing).</summary>
    public byte[] GetReassembledBytes()
    {
        lock (_gate) return _reassembled.ToArray();
    }

    public void MarkStreamStart(uint isn)
    {
        lock (_gate) _nextExpectedSeq ??= isn;
    }

    public void AddSegment(uint seq, ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0) return;

        lock (_gate) AddSegmentCore(seq, payload);
    }

    private void AddSegmentCore(uint seq, ReadOnlySpan<byte> payload)
    {
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

/// <summary>
/// One piece of a conversation as it appeared on the wire: which way it went, when, and what
/// it said. The direction buffers answer "what did this side send in total"; these answer
/// "what was said, in what order" - which is the only way to read a request and its response
/// as a dialogue rather than as two separate walls of text.
/// </summary>
public sealed record StreamChunk(bool FromA, DateTimeOffset Timestamp, uint Sequence, byte[] Data);

public sealed class TcpStream
{
    /// <summary>
    /// Ceiling on the replay log. It duplicates payload that is already in the direction
    /// buffers, so it is capped well below them: a conversation nobody can read to the end is
    /// not worth the memory, and the reassembled totals stay complete either way.
    /// </summary>
    private const long MaxConversationBytes = 4 * 1024 * 1024;

    private readonly List<StreamChunk> _conversation = [];
    private readonly object _gate = new();
    private long _conversationBytes;

    public required TcpStreamKey Key { get; init; }
    public TcpDirectionBuffer AToB { get; } = new();
    public TcpDirectionBuffer BToA { get; } = new();
    public DateTimeOffset LastActivity { get; set; }

    /// <summary>True once the log stopped growing, so a view can say so rather than imply the
    /// conversation simply ended.</summary>
    public bool ConversationTruncated { get; private set; }

    /// <summary>The conversation in capture order. A snapshot: the capture keeps going.</summary>
    public IReadOnlyList<StreamChunk> Conversation
    {
        get { lock (_gate) return [.. _conversation]; }
    }

    internal void Record(bool fromA, DateTimeOffset timestamp, uint sequence, ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0) return;

        lock (_gate)
        {
            if (_conversationBytes + payload.Length > MaxConversationBytes)
            {
                ConversationTruncated = true;
                return;
            }

            _conversation.Add(new StreamChunk(fromA, timestamp, sequence, payload.ToArray()));
            _conversationBytes += payload.Length;
        }
    }
}
