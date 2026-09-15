using System.Net;
using NetSniffer.Core.Model;
using NetSniffer.Core.Naming;
using NetSniffer.Core.Parsing;

/// <summary>
/// QUIC dissection and the passive name registry - the two things that turn a wall of
/// "UDP 443" rows into named hosts.
/// </summary>
public static class NamingTests
{
    /// <summary>
    /// The client Initial packet from RFC 9001 Appendix A.2, verbatim. Its CRYPTO frame carries
    /// a ClientHello for "example.com", so decrypting it end to end exercises the whole path:
    /// key derivation from the connection ID, header-protection removal, AES-GCM, frame walking
    /// and the ClientHello parse. Any mistake anywhere and the AEAD tag simply won't verify.
    /// </summary>
    private const string Rfc9001ClientInitial =
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c" +
        "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89" +
        "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e" +
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7" +
        "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7" +
        "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf" +
        "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2" +
        "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd" +
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07" +
        "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d" +
        "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723" +
        "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd" +
        "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
    public static void Run()
    {
        T.Section("QUIC + NAME RESOLUTION");

        byte[] quic = Convert.FromHexString(Rfc9001ClientInitial);
        T.Eq("RFC 9001 A.2 sample is 1200 bytes", 1200, quic.Length);

        var initial = Parse(B.Ethernet(0x0800, B.IPv4(17, "192.168.1.5", "93.184.216.34",
            B.Udp(54321, 443, quic))));

        T.Eq("QUIC recognised on UDP 443", "QUIC", initial.Protocol);
        T.Check("QUIC Initial decrypted to the SNI", initial.Info.Contains("example.com"), initial.Info);

        var quicLayer = initial.Layers.Single(l => l.Name == "QUIC");
        T.Check("long header reported",
            quicLayer.Fields.Any(f => f.Name == "Header Form" && f.Value == "Long"));
        T.Check("version 1 reported",
            quicLayer.Fields.Any(f => f.Name == "Version" && f.Value.Contains("RFC 9000")),
            string.Join(",", quicLayer.Fields.Select(f => f.Name + "=" + f.Value)));
        T.Check("connection ID from the RFC sample",
            quicLayer.Fields.Any(f => f.Name == "Destination Connection ID" && f.Value == "8394c8f03e515708"));
        T.Check("SNI recorded as a name hint for the destination",
            initial.NameHints is { Count: > 0 } hints
            && hints.Any(h => h.Name == "example.com"
                              && h.Source == NameHintSource.TlsSni
                              && Equals(h.Address, IPAddress.Parse("93.184.216.34"))));

        // A truncated or corrupted Initial must degrade to "encrypted", never throw.
        byte[] damaged = (byte[])quic.Clone();
        damaged[900] ^= 0xFF; // inside the AEAD-protected payload
        var broken = Parse(B.Ethernet(0x0800, B.IPv4(17, "192.168.1.5", "93.184.216.34",
            B.Udp(54321, 443, damaged))));
        T.Eq("tampered Initial still dissects as QUIC", "QUIC", broken.Protocol);
        T.Check("tampered Initial yields no SNI", !broken.Info.Contains("example.com"), broken.Info);

        var shortHeader = Parse(B.Ethernet(0x0800, B.IPv4(17, "10.0.0.2", "10.0.0.3",
            B.Udp(443, 55000, [0x40, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04]))));
        T.Eq("QUIC short header labelled, not misparsed", "QUIC", shortHeader.Protocol);

        // ---- DNS answers feed the registry
        var registry = new HostNameRegistry();
        var dnsResponse = Parse(B.Ethernet(0x0800, B.IPv4(17, "1.1.1.1", "192.168.1.5",
            B.Udp(53, 51000, B.DnsResponse(0xBEEF, "www.github.com", IPAddress.Parse("140.82.121.4"))))));

        T.Eq("DNS response dissected", "DNS", dnsResponse.Protocol);
        registry.Ingest(dnsResponse);
        T.Check("A record teaches the registry a name",
            registry.TryGetName(IPAddress.Parse("140.82.121.4"), out var learned) && learned == "www.github.com",
            learned);

        T.Eq("unknown address stays an address", "8.8.8.8",
            registry.Describe(IPAddress.Parse("8.8.8.8"), 0));
        T.Eq("known address renders as the domain with its port", "www.github.com:443",
            registry.Describe(IPAddress.Parse("140.82.121.4"), 443));

        // A DNS answer must win over an SNI for the same address.
        registry.Ingest(initial);
        registry.Ingest(dnsResponse);
        T.Check("DNS answer outranks a later SNI",
            registry.TryGetName(IPAddress.Parse("140.82.121.4"), out var kept) && kept == "www.github.com", kept);

        // ---- Host rollup
        var tracker = new HostTrafficTracker([IPAddress.Parse("192.168.1.5")]);
        for (int i = 0; i < 5; i++)
        {
            var outbound = Parse(B.Ethernet(0x0800, B.IPv4(6, "192.168.1.5", "140.82.121.4",
                B.Tcp(40000, 443, 1, 1, 0x18, [1, 2, 3, 4]))));
            tracker.Ingest(outbound, registry);
        }

        var hosts = tracker.Snapshot();
        T.Eq("one remote host tracked", 1, hosts.Count);
        T.Eq("remote side chosen, not our own address", "140.82.121.4", hosts[0].Address.ToString());
        T.Eq("packets counted", 5L, hosts[0].Packets);
        T.Eq("host labelled with its domain", "www.github.com", hosts[0].Name);
        T.Check("remote port recorded", hosts[0].Ports.Contains(443));
        T.Check("direction split kept", hosts[0].SentBytes > 0 && hosts[0].ReceivedBytes == 0);

        // ---- Process attribution picks OUR port, in both directions
        var asked = new List<(bool Tcp, ushort Port)>();
        var attributing = new HostTrafficTracker(
            [IPAddress.Parse("192.168.1.5")],
            (tcp, port) =>
            {
                asked.Add((tcp, port));
                return port == 40000 ? new LocalProcess("chrome", @"C:\chrome.exe")
                     : port == 55123 ? new LocalProcess("Telegram", null)
                     : null;
            });

        var sent = Parse(B.Ethernet(0x0800, B.IPv4(6, "192.168.1.5", "140.82.121.4",
            B.Tcp(40000, 443, 1, 1, 0x18, [1]))));
        attributing.Ingest(sent, registry);
        var received = Parse(B.Ethernet(0x0800, B.IPv4(17, "149.154.167.51", "192.168.1.5",
            B.Udp(443, 55123, [0x40, 1, 2, 3]))));
        attributing.Ingest(received, registry);

        T.Check("outbound packet asks about its source port, over TCP", asked.Contains((true, 40000)),
            string.Join(",", asked));
        T.Check("inbound packet asks about its destination port, over UDP", asked.Contains((false, 55123)),
            string.Join(",", asked));
        T.Eq("packet labelled with its program", "chrome", sent.ProcessName ?? "");
        T.Eq("inbound packet labelled too", "Telegram", received.ProcessName ?? "");
        T.Check("host remembers which programs used it",
            attributing.Snapshot().Single(h => h.Address.ToString() == "140.82.121.4").Processes.ContainsKey("chrome"));

        var icmpOnly = Parse(B.Ethernet(0x0800, B.IPv4(1, "192.168.1.5", "8.8.8.8", [8, 0, 0, 0, 0, 1, 0, 1])));
        int before = asked.Count;
        attributing.Ingest(icmpOnly, registry);
        T.Eq("ICMP never asks for a process (no sockets)", before, asked.Count);

        // Broadcast and multicast would otherwise swamp the host list.
        tracker.Ingest(Parse(B.Ethernet(0x0800, B.IPv4(17, "192.168.1.5", "239.255.255.250",
            B.Udp(50000, 1900, [1, 2, 3])))), registry);
        tracker.Ingest(Parse(B.Ethernet(0x0800, B.IPv4(17, "192.168.1.5", "255.255.255.255",
            B.Udp(68, 67, [1, 2, 3])))), registry);
        T.Eq("multicast and broadcast excluded from hosts", 1, tracker.Snapshot().Count);
    }

    private static ParsedPacket Parse(byte[] frame) =>
        PacketParser.Parse(new CapturedPacket(1, DateTimeOffset.Now, frame, frame.Length));
}
