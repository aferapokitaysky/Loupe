using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using Loupe.Core.IO;
using Loupe.Core.Model;
using Loupe.Core.Parsing;
using Loupe.Core.Tcp;
using Loupe.Proxy;
using Loupe.Proxy.Ca;
using Loupe.Proxy.Http;

Console.OutputEncoding = Encoding.UTF8;

static ParsedPacket Parse(byte[] frame) =>
    PacketParser.Parse(new CapturedPacket(1, DateTimeOffset.Now, frame, frame.Length));

// ---------------------------------------------------------------- dissector
T.Section("DISSECTOR");
{
    var tcpFrame = B.Ethernet(0x0800, B.IPv4(6, "192.168.1.5", "93.184.216.34",
        B.Tcp(52344, 443, 1000, 2000, 0x18, B.TlsClientHello("example.org"))));
    var p = Parse(tcpFrame);
    T.Eq("TCP/TLS protocol", "TLS", p.Protocol);
    T.Eq("TCP source endpoint", "192.168.1.5:52344", p.Source);
    T.Check("TLS SNI extracted", p.Info.Contains("example.org"), p.Info);
    T.Check("layer tree has Ethernet/IPv4/TCP/TLS",
        p.Layers.Select(l => l.Name).SequenceEqual(["Ethernet II", "IPv4", "TCP", "TLS"]),
        string.Join(",", p.Layers.Select(l => l.Name)));
    T.Check("TcpInfo populated", p.Tcp is { SourcePort: 52344, DestinationPort: 443, SequenceNumber: 1000 });
    T.Check("TCP flags shown", p.Layers[2].Fields.Any(f => f.Value.Contains("PSH") && f.Value.Contains("ACK")));

    var dns = Parse(B.Ethernet(0x0800, B.IPv4(17, "192.168.1.5", "1.1.1.1",
        B.Udp(51000, 53, B.DnsQuery(0xBEEF, "www.github.com")))));
    T.Eq("DNS protocol", "DNS", dns.Protocol);
    T.Check("DNS question name", dns.Info.Contains("www.github.com"), dns.Info);

    var arp = Parse(B.Ethernet(0x0806, B.Arp("192.168.1.5", "192.168.1.1", 1)));
    T.Eq("ARP protocol", "ARP", arp.Protocol);
    T.Check("ARP request wording", arp.Info.Contains("192.168.1.1") && arp.Info.Contains("192.168.1.5"), arp.Info);

    var icmp = Parse(B.Ethernet(0x0800, B.IPv4(1, "10.0.0.1", "10.0.0.2", [8, 0, 0, 0, 0, 1, 0, 1])));
    T.Eq("ICMP protocol", "ICMP", icmp.Protocol);

    var v6 = Parse(B.Ethernet(0x86DD, B.IPv6(17, "2001:db8::1", "2001:db8::2", B.Udp(1234, 5678, [1, 2, 3, 4]))));
    T.Eq("IPv6+UDP protocol", "UDP", v6.Protocol);
    T.Eq("IPv6 source endpoint", "2001:db8::1:1234", v6.Source);

    var http = Parse(B.Ethernet(0x0800, B.IPv4(6, "10.0.0.1", "10.0.0.2",
        B.Tcp(40000, 80, 1, 1, 0x18, Encoding.ASCII.GetBytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")))));
    T.Eq("HTTP protocol", "HTTP", http.Protocol);
    T.Check("HTTP host parsed", http.Info.Contains("example.com"), http.Info);

    // Truncated / garbage frames must never throw
    try
    {
        Parse([0x00, 0x01, 0x02]);
        Parse(B.Ethernet(0x0800, [0x45, 0x00]));
        Parse(B.Ethernet(0x0800, B.IPv4(6, "1.1.1.1", "2.2.2.2", [0x00, 0x01])));
        T.Check("malformed frames don't throw", true);
    }
    catch (Exception ex) { T.Check("malformed frames don't throw", false, ex.Message); }
}

// ---------------------------------------------------------------- pcap I/O
T.Section("PCAP FILE I/O");
{
    var path = Path.Combine(Path.GetTempPath(), $"ns-test-{Guid.NewGuid():N}.pcap");
    var ts = new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero).AddTicks(1234560); // .123456 s
    var original = new List<CapturedPacket>
    {
        new(1, ts, B.Ethernet(0x0800, B.IPv4(6, "10.0.0.1", "10.0.0.2", B.Tcp(1, 2, 3, 4, 0x10, [9, 9, 9]))), 60),
        new(2, ts.AddSeconds(1.5), B.Ethernet(0x0806, B.Arp("10.0.0.1", "10.0.0.9", 2)), 42),
    };
    PcapFile.Write(path, original);
    var read = PcapFile.Read(path).ToList();

    T.Eq("packet count round-trips", 2, read.Count);
    T.Check("payload bytes round-trip", read[0].Data.SequenceEqual(original[0].Data));
    T.Eq("original length round-trips", 60, read[0].OriginalLength);
    T.Eq("timestamp seconds round-trip", ts.ToUnixTimeSeconds(), read[0].Timestamp.ToUnixTimeSeconds());
    T.Eq("timestamp microseconds round-trip", 123456, (read[0].Timestamp.UtcDateTime.Ticks / 10) % 1_000_000);
    T.Check("second packet parses after round-trip", Parse(read[1].Data).Protocol == "ARP");
    File.Delete(path);
}

// ---------------------------------------------------------------- reassembly
T.Section("TCP REASSEMBLY");
{
    static ParsedPacket Seg(uint seq, string text, bool syn = false) => Parse(B.Ethernet(0x0800,
        B.IPv4(6, "10.0.0.1", "10.0.0.2", B.Tcp(1111, 80, seq, 0, (byte)(syn ? 0x02 : 0x18),
            Encoding.ASCII.GetBytes(text)))));

    var r = new TcpStreamReassembler();
    r.Ingest(Seg(1000, "", syn: true));           // ISN 1000 -> data starts at 1001
    r.Ingest(Seg(1001, "HELLO "));
    r.Ingest(Seg(1013, "WORLD"));                  // arrives early (gap)
    r.Ingest(Seg(1007, "BRAVE "));                 // fills the gap
    var stream = r.Streams.Single();
    var key = stream.Key;
    var buf = key.IsAToB("10.0.0.1", 1111) ? stream.AToB : stream.BToA;
    T.Eq("out-of-order segments reassemble in order", "HELLO BRAVE WORLD",
        Encoding.ASCII.GetString(buf.GetReassembledBytes()));

    var r2 = new TcpStreamReassembler();
    r2.Ingest(Seg(500, "", syn: true));
    r2.Ingest(Seg(501, "ABCDEF"));
    r2.Ingest(Seg(501, "ABCDEF"));                 // exact retransmission
    r2.Ingest(Seg(504, "DEFGHI"));                 // overlapping retransmission + new tail
    var s2 = r2.Streams.Single();
    var b2 = s2.Key.IsAToB("10.0.0.1", 1111) ? s2.AToB : s2.BToA;
    T.Eq("retransmits/overlap dedupe", "ABCDEFGHI", Encoding.ASCII.GetString(b2.GetReassembledBytes()));

    var r3 = new TcpStreamReassembler();
    r3.Ingest(Seg(uint.MaxValue - 2, "", syn: true)); // ISN near wrap -> data starts at MaxValue-1
    r3.Ingest(Seg(uint.MaxValue - 1, "XY"));          // consumes MaxValue-1 and MaxValue
    r3.Ingest(Seg(0, "Z"));                           // first byte after the wrap
    var s3 = r3.Streams.Single();
    var b3 = s3.Key.IsAToB("10.0.0.1", 1111) ? s3.AToB : s3.BToA;
    T.Eq("in-order sequence wraparound", "XYZ", Encoding.ASCII.GetString(b3.GetReassembledBytes()));

    // Out-of-order across the wrap: a post-wrap segment (low key) is buffered while the
    // segments still needed are high keys. Draining by "smallest pending key" stalls here.
    // Byte layout: AB at MaxValue-5..-4, CD at -3..-2, EF at -1..MaxValue, then G at 0.
    var r4 = new TcpStreamReassembler();
    r4.Ingest(Seg(uint.MaxValue - 6, "", syn: true)); // data starts at MaxValue-5
    r4.Ingest(Seg(0, "G"));                           // arrives first, lives past the wrap
    r4.Ingest(Seg(uint.MaxValue - 1, "EF"));
    r4.Ingest(Seg(uint.MaxValue - 3, "CD"));
    r4.Ingest(Seg(uint.MaxValue - 5, "AB"));          // fills the gap, should cascade through all of it
    var s4 = r4.Streams.Single();
    var b4 = s4.Key.IsAToB("10.0.0.1", 1111) ? s4.AToB : s4.BToA;
    T.Eq("out-of-order across wraparound drains fully", "ABCDEFG", Encoding.ASCII.GetString(b4.GetReassembledBytes()));

    // A gap that never fills must not pin memory forever.
    var r5 = new TcpStreamReassembler();
    r5.Ingest(Seg(100, "", syn: true));               // data starts at 101
    for (uint i = 0; i < 400; i++)                    // 400 x 8 KB, all after a missing first segment
        r5.Ingest(Seg(200_000 + i * 8192, new string('x', 8192)));
    T.Check("unfillable gap doesn't buffer without bound", GC.GetTotalMemory(true) < 200_000_000);

    T.Eq("both directions share one stream key",
        1, new TcpStreamKey("1.1.1.1", 80, "2.2.2.2", 9) == new TcpStreamKey("2.2.2.2", 9, "1.1.1.1", 80) ? 1 : 0);
}

NamingTests.Run();

StorageTests.Run();

SessionTests.Run();

HarTests.Run();

await ProxyTests.RunAsync();

await TransparentTests.RunAsync();

await ProcessTests.RunAsync();

Console.WriteLine($"\n================  {T.Pass} passed, {T.Fail} failed  ================");
return T.Fail == 0 ? 0 : 1;
