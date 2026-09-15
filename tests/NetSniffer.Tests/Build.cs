using System.Buffers.Binary;
using System.Net;

/// <summary>Minimal packet builders so the dissector can be tested without a live adapter.</summary>
public static class B
{
    public static byte[] Ethernet(ushort etherType, byte[] payload)
    {
        var f = new byte[14 + payload.Length];
        for (int i = 0; i < 6; i++) { f[i] = (byte)(0xA0 + i); f[6 + i] = (byte)(0xB0 + i); }
        BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(12), etherType);
        payload.CopyTo(f, 14);
        return f;
    }

    public static byte[] IPv4(byte protocol, string src, string dst, byte[] payload)
    {
        var p = new byte[20 + payload.Length];
        p[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(6), 0x4000); // DF
        p[8] = 64; p[9] = protocol;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
        payload.CopyTo(p, 20);
        return p;
    }

    public static byte[] IPv6(byte nextHeader, string src, string dst, byte[] payload)
    {
        var p = new byte[40 + payload.Length];
        p[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), (ushort)payload.Length);
        p[6] = nextHeader; p[7] = 64;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 8);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 24);
        payload.CopyTo(p, 40);
        return p;
    }

    public static byte[] Tcp(ushort sport, ushort dport, uint seq, uint ack, byte flags, byte[] payload)
    {
        var t = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(0), sport);
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(2), dport);
        BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(8), ack);
        t[12] = 0x50; t[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(14), 64240);
        payload.CopyTo(t, 20);
        return t;
    }

    public static byte[] Udp(ushort sport, ushort dport, byte[] payload)
    {
        var u = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(0), sport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(2), dport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(4), (ushort)u.Length);
        payload.CopyTo(u, 8);
        return u;
    }

    public static byte[] Arp(string senderIp, string targetIp, ushort opcode)
    {
        var a = new byte[28];
        BinaryPrimitives.WriteUInt16BigEndian(a.AsSpan(0), 1);
        BinaryPrimitives.WriteUInt16BigEndian(a.AsSpan(2), 0x0800);
        a[4] = 6; a[5] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(a.AsSpan(6), opcode);
        for (int i = 0; i < 6; i++) { a[8 + i] = (byte)(0xC0 + i); a[18 + i] = (byte)(0xD0 + i); }
        IPAddress.Parse(senderIp).GetAddressBytes().CopyTo(a, 14);
        IPAddress.Parse(targetIp).GetAddressBytes().CopyTo(a, 24);
        return a;
    }

    public static byte[] DnsQuery(ushort id, string name, ushort qtype = 1)
    {
        var body = new List<byte>();
        body.AddRange([(byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        foreach (var label in name.Split('.'))
        {
            body.Add((byte)label.Length);
            body.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        body.Add(0);
        body.AddRange([(byte)(qtype >> 8), (byte)qtype, 0, 1]);
        return [.. body];
    }

    /// <summary>A DNS response: one question echoed back, then one A or AAAA answer for it.</summary>
    public static byte[] DnsResponse(ushort id, string name, System.Net.IPAddress address)
    {
        var body = new List<byte>();
        body.AddRange([(byte)(id >> 8), (byte)id, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);

        var encodedName = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            encodedName.Add((byte)label.Length);
            encodedName.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        encodedName.Add(0);

        byte[] rdata = address.GetAddressBytes();
        ushort qtype = (ushort)(rdata.Length == 4 ? 1 : 28);

        body.AddRange(encodedName);                                       // question
        body.AddRange([(byte)(qtype >> 8), (byte)qtype, 0, 1]);

        // Answer: a compression pointer back to the question's name, as a real resolver sends.
        body.AddRange([0xC0, 0x0C]);
        body.AddRange([(byte)(qtype >> 8), (byte)qtype, 0, 1]);           // type, class IN
        body.AddRange([0, 0, 0x01, 0x2C]);                                // TTL 300
        body.AddRange([(byte)(rdata.Length >> 8), (byte)rdata.Length]);
        body.AddRange(rdata);
        return [.. body];
    }

    /// <summary>TLS 1.2-style ClientHello carrying a server_name (SNI) extension.</summary>
    public static byte[] TlsClientHello(string sni)
    {
        var sniBytes = System.Text.Encoding.ASCII.GetBytes(sni);
        var serverNameList = new List<byte> { 0 };                            // name type: host_name
        serverNameList.AddRange([(byte)(sniBytes.Length >> 8), (byte)sniBytes.Length]);
        serverNameList.AddRange(sniBytes);
        var extBody = new List<byte> { (byte)(serverNameList.Count >> 8), (byte)serverNameList.Count };
        extBody.AddRange(serverNameList);

        var ext = new List<byte> { 0x00, 0x00, (byte)(extBody.Count >> 8), (byte)extBody.Count };
        ext.AddRange(extBody);

        var hello = new List<byte> { 0x03, 0x03 };                             // client version
        hello.AddRange(new byte[32]);                                          // random
        hello.Add(0);                                                          // session id len
        hello.AddRange([0x00, 0x02, 0x13, 0x01]);                              // cipher suites
        hello.AddRange([0x01, 0x00]);                                          // compression
        hello.AddRange([(byte)(ext.Count >> 8), (byte)ext.Count]);
        hello.AddRange(ext);

        var handshake = new List<byte> { 0x01, (byte)(hello.Count >> 16), (byte)(hello.Count >> 8), (byte)hello.Count };
        handshake.AddRange(hello);

        var record = new List<byte> { 0x16, 0x03, 0x01, (byte)(handshake.Count >> 8), (byte)handshake.Count };
        record.AddRange(handshake);
        return [.. record];
    }
}
