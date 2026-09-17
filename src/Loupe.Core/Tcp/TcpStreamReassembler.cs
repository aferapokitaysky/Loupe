using System.Collections.Concurrent;
using Loupe.Core.Model;

namespace Loupe.Core.Tcp;

/// <summary>
/// Tracks every TCP connection seen so far and reassembles each direction's
/// byte stream from possibly out-of-order segments, so the UI can show
/// "Follow TCP Stream"-style reconstructed request/response bodies.
/// </summary>
public sealed class TcpStreamReassembler
{
    private readonly ConcurrentDictionary<TcpStreamKey, TcpStream> _streams = new();

    public IReadOnlyCollection<TcpStream> Streams => (IReadOnlyCollection<TcpStream>)_streams.Values;

    /// <summary>Feeds one dissected packet into its stream's reassembly buffers. No-op for non-TCP packets.</summary>
    public TcpStream? Ingest(ParsedPacket packet)
    {
        var tcp = packet.Tcp;
        if (tcp is null) return null;

        var key = new TcpStreamKey(tcp.SourceIp, tcp.SourcePort, tcp.DestinationIp, tcp.DestinationPort);
        var stream = _streams.GetOrAdd(key, k => new TcpStream { Key = k });
        stream.LastActivity = packet.Timestamp;

        var buffer = key.IsAToB(tcp.SourceIp, tcp.SourcePort) ? stream.AToB : stream.BToA;

        if (tcp.IsSyn) buffer.MarkStreamStart(tcp.SequenceNumber + 1);

        if (tcp.PayloadLength > 0 && tcp.PayloadOffset + tcp.PayloadLength <= packet.RawData.Length)
        {
            var payload = packet.RawData.AsSpan(tcp.PayloadOffset, tcp.PayloadLength);
            buffer.AddSegment(tcp.SequenceNumber, payload);

            // Kept alongside the per-direction reassembly, because the two answer different
            // questions: that one is "what did this side send", this one is "who said what,
            // when" - the difference between two walls of text and a readable dialogue.
            stream.Record(key.IsAToB(tcp.SourceIp, tcp.SourcePort), packet.Timestamp, tcp.SequenceNumber, payload);
        }

        return stream;
    }

    public TcpStream? TryGetStream(TcpStreamKey key) => _streams.GetValueOrDefault(key);

    public void Clear() => _streams.Clear();
}
