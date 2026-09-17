using System.Text;
using Loupe.Core.IO;
using Loupe.Core.Model;
using Loupe.Core.Parsing;
using Loupe.Core.Tcp;
using Loupe.Core.Util;

/// <summary>
/// What the "follow this stream" pane is made of: both directions of one conversation put
/// back together from frames that did not arrive in order, and rendered so that binary
/// payloads stay in their pane instead of scrambling it.
/// </summary>
public static class FollowTests
{
    public static void Run()
    {
        T.Section("FOLLOW STREAM");

        static ParsedPacket Parse(byte[] frame) =>
            PacketParser.Parse(new CapturedPacket(1, DateTimeOffset.Now, frame, frame.Length));

        static byte[] Frame(string src, ushort srcPort, string dst, ushort dstPort, uint seq, byte flags, string text) =>
            B.Ethernet(0x0800, B.IPv4(6, src, dst, B.Tcp(srcPort, dstPort, seq, 0, flags, Encoding.ASCII.GetBytes(text))));

        const string Client = "192.168.1.24";
        const string Server = "93.184.216.34";
        const ushort ClientPort = 54321;

        string request = "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";
        string head = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n";
        string tail = "It works!";

        var reassembler = new TcpStreamReassembler();
        reassembler.Ingest(Parse(Frame(Client, ClientPort, Server, 80, 1000, 0x02, "")));   // SYN, ISN 1000
        reassembler.Ingest(Parse(Frame(Server, 80, Client, ClientPort, 5000, 0x12, "")));   // SYN/ACK, ISN 5000
        reassembler.Ingest(Parse(Frame(Client, ClientPort, Server, 80, 1001, 0x18, request)));

        // The response's second half overtakes its first - the case the pane exists to survive.
        reassembler.Ingest(Parse(Frame(Server, 80, Client, ClientPort, 5001 + (uint)head.Length, 0x18, tail)));
        reassembler.Ingest(Parse(Frame(Server, 80, Client, ClientPort, 5001, 0x18, head)));

        var stream = reassembler.Streams.Single();
        bool clientIsA = stream.Key.IsAToB(Client, ClientPort);
        var sent = clientIsA ? stream.AToB : stream.BToA;
        var received = clientIsA ? stream.BToA : stream.AToB;

        T.Eq("the request side reassembles", request, StreamText.Readable(sent.GetReassembledBytes()));
        T.Eq("the response side reassembles in order despite arriving reversed",
            head + tail, StreamText.Readable(received.GetReassembledBytes()));
        T.Eq("byte counts match what was sent", (long)request.Length, sent.TotalBytes);

        // Both ends of a conversation are one stream, whichever end you picked.
        T.Check("the same stream is found from either direction",
            reassembler.TryGetStream(new TcpStreamKey(Client, ClientPort, Server, 80)) ==
            reassembler.TryGetStream(new TcpStreamKey(Server, 80, Client, ClientPort)));

        // The dialogue log: who said what, in the order they said it.
        var conversation = stream.Conversation;
        T.Eq("every payload-bearing packet is logged as a turn piece", 3, conversation.Count);
        T.Check("the request is logged as sent by the client",
            conversation[0].FromA == clientIsA && StreamText.Readable(conversation[0].Data) == request);
        T.Check("both response pieces are logged as the server's",
            conversation[1].FromA != clientIsA && conversation[2].FromA != clientIsA);
        T.Check("pieces carry their sequence number, so a turn can be put back in order",
            conversation[1].Sequence > conversation[2].Sequence,
            $"{conversation[1].Sequence} then {conversation[2].Sequence}");
        T.Check("pieces carry when they arrived", conversation.All(c => c.Timestamp != default));

        // The response halves arrived reversed; ordering the turn by sequence is what turns
        // them back into one readable answer.
        var ordered = conversation
            .Where(c => c.FromA != clientIsA)
            .OrderBy(c => c.Sequence)
            .SelectMany(c => c.Data)
            .ToArray();
        T.Eq("a turn reads in send order once sorted by sequence", head + tail, StreamText.Readable(ordered));

        // A TLS record in a text pane: no escape sequences, no bell, nothing swallowed.
        byte[] binary = [0x16, 0x03, 0x01, 0x00, 0x07, 0x1B, 0x07, (byte)'o', (byte)'k', 0x00, (byte)'\n'];
        string rendered = StreamText.Readable(binary);
        T.Eq("unprintable bytes render as dots", ".......ok.\n", rendered);
        T.Check("no control characters survive rendering",
            !rendered.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t')), rendered);
        T.Eq("line breaks are kept", 1, rendered.Count(c => c == '\n'));
        T.Eq("empty input renders empty", "", StreamText.Readable([]));

        // A capture that starts mid-stream has no SYN to anchor on; the first segment seen
        // becomes the origin rather than the direction staying empty forever.
        var midStream = new TcpStreamReassembler();
        midStream.Ingest(Parse(Frame(Client, 40000, Server, 443, 987_654, 0x18, "already-running")));
        T.Eq("a stream joined late still reassembles", "already-running",
            StreamText.Readable(midStream.Streams.Single().AToB.GetReassembledBytes()));

        // The pcap round-trip the "open a capture file" path relies on.
        string path = Path.Combine(Path.GetTempPath(), $"loupe-follow-{Guid.NewGuid():N}.pcap");
        PcapFile.Write(path, [new CapturedPacket(1, DateTimeOffset.Now, Frame(Client, ClientPort, Server, 80, 1001, 0x18, request), 0)]);
        var reloaded = new TcpStreamReassembler();
        foreach (var captured in PcapFile.Read(path))
            reloaded.Ingest(PacketParser.Parse(captured));
        T.Eq("a stream survives a pcap round-trip", request,
            StreamText.Readable(reloaded.Streams.Single().AToB.GetReassembledBytes()));
        File.Delete(path);
    }
}
