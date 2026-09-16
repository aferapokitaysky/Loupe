using System.Net;
using System.Net.NetworkInformation;
using Loupe.Core.Model;
using Loupe.Core.Util;

namespace Loupe.Core.Parsing;

/// <summary>
/// Dissects a raw Ethernet frame into a <see cref="ParsedPacket"/> layer tree.
/// Covers Ethernet II, ARP, IPv4/IPv6, ICMP/ICMPv6, TCP/UDP, and best-effort
/// application-layer identification (DNS, TLS ClientHello/ServerHello + SNI).
/// Unknown protocols degrade gracefully to a single "Data" layer rather than throwing.
/// </summary>
public static class PacketParser
{
    public static ParsedPacket Parse(CapturedPacket captured)
    {
        var packet = new ParsedPacket
        {
            Number = captured.Number,
            Timestamp = captured.Timestamp,
            RawData = captured.Data,
            OriginalLength = captured.OriginalLength,
            Protocol = "Unknown",
            Info = "",
        };

        try
        {
            ParseEthernet(captured.Data, packet);
        }
        catch (Exception ex)
        {
            // Malformed/truncated capture: keep what we parsed so far and
            // surface the rest as an error note instead of losing the packet.
            packet.Layers.Add(new PacketLayer { Name = "Malformed", Offset = 0, Length = captured.Data.Length }
                .With("Error", ex.Message, 0, 0));
            if (packet.Protocol == "Unknown") packet.Protocol = "Malformed";
        }

        return packet;
    }

    private static void ParseEthernet(byte[] data, ParsedPacket packet)
    {
        if (data.Length < 14)
        {
            packet.Protocol = "Raw";
            packet.Info = $"{data.Length} byte frame (too short for Ethernet)";
            return;
        }

        var reader = new ByteReader(data);
        var dest = PhysicalAddress.Parse(Convert.ToHexString(reader.ReadBytes(6)));
        var src = PhysicalAddress.Parse(Convert.ToHexString(reader.ReadBytes(6)));
        ushort etherType = reader.ReadUInt16();

        var layer = new PacketLayer { Name = "Ethernet II", Offset = 0, Length = 14 }
            .With("Destination", FormatMac(dest), 0, 6)
            .With("Source", FormatMac(src), 6, 6)
            .With("Type", $"0x{etherType:X4} ({EtherTypeName(etherType)})", 12, 2);
        packet.Layers.Add(layer);

        packet.Source = FormatMac(src);
        packet.Destination = FormatMac(dest);
        packet.Protocol = EtherTypeName(etherType);

        switch (etherType)
        {
            case 0x0800: ParseIPv4(data, 14, packet); break;
            case 0x86DD: ParseIPv6(data, 14, packet); break;
            case 0x0806: ParseArp(data, 14, packet); break;
            default:
                packet.Info = $"Ethertype 0x{etherType:X4}, {data.Length - 14} bytes payload";
                break;
        }
    }

    private static void ParseArp(byte[] data, int offset, ParsedPacket packet)
    {
        if (data.Length - offset < 28) return;
        var r = new ByteReader(data, offset);
        r.Skip(6); // hw type, proto type, hw len, proto len, opcode (partially read below)
        ushort opcode = BinaryPeek16(data, offset + 6);
        var senderMac = PhysicalAddress.Parse(Convert.ToHexString(data.AsSpan(offset + 8, 6)));
        var senderIp = new IPAddress(data.AsSpan(offset + 14, 4));
        var targetMac = PhysicalAddress.Parse(Convert.ToHexString(data.AsSpan(offset + 18, 6)));
        var targetIp = new IPAddress(data.AsSpan(offset + 24, 4));

        var layer = new PacketLayer { Name = "ARP", Offset = offset, Length = 28 }
            .With("Opcode", opcode == 1 ? "Request" : opcode == 2 ? "Reply" : opcode.ToString(), offset + 6, 2)
            .With("Sender MAC", FormatMac(senderMac), offset + 8, 6)
            .With("Sender IP", senderIp.ToString(), offset + 14, 4)
            .With("Target MAC", FormatMac(targetMac), offset + 18, 6)
            .With("Target IP", targetIp.ToString(), offset + 24, 4);
        packet.Layers.Add(layer);

        packet.Source = senderIp.ToString();
        packet.Destination = targetIp.ToString();
        packet.Protocol = "ARP";
        packet.Info = opcode == 1
            ? $"Who has {targetIp}? Tell {senderIp}"
            : $"{senderIp} is at {FormatMac(senderMac)}";
    }

    private static void ParseIPv4(byte[] data, int offset, ParsedPacket packet)
    {
        if (data.Length - offset < 20) return;
        var r = new ByteReader(data, offset);

        byte versionAndIhl = r.ReadByte();
        int headerLength = (versionAndIhl & 0x0F) * 4;
        byte dscp = r.ReadByte();
        ushort totalLength = r.ReadUInt16();
        ushort id = r.ReadUInt16();
        ushort flagsAndFragment = r.ReadUInt16();
        byte ttl = r.ReadByte();
        byte protocol = r.ReadByte();
        ushort checksum = r.ReadUInt16();
        var srcIp = new IPAddress(r.ReadBytes(4));
        var dstIp = new IPAddress(r.ReadBytes(4));

        var layer = new PacketLayer { Name = "IPv4", Offset = offset, Length = headerLength }
            .With("Version", "4", offset, 1)
            .With("Header Length", $"{headerLength} bytes", offset, 1)
            .With("Total Length", totalLength.ToString(), offset + 2, 2)
            .With("Identification", $"0x{id:X4}", offset + 4, 2)
            .With("Flags", DescribeIPv4Flags(flagsAndFragment), offset + 6, 2)
            .With("TTL", ttl.ToString(), offset + 8, 1)
            .With("Protocol", $"{protocol} ({IpProtocolName(protocol)})", offset + 9, 1)
            .With("Header Checksum", $"0x{checksum:X4}", offset + 10, 2)
            .With("Source", srcIp.ToString(), offset + 12, 4)
            .With("Destination", dstIp.ToString(), offset + 16, 4);
        packet.Layers.Add(layer);

        packet.Source = srcIp.ToString();
        packet.Destination = dstIp.ToString();
        packet.SourceAddress = srcIp;
        packet.DestinationAddress = dstIp;
        packet.Protocol = IpProtocolName(protocol);

        int payloadOffset = offset + headerLength;
        DispatchTransport(protocol, data, payloadOffset, packet);
    }

    private static void ParseIPv6(byte[] data, int offset, ParsedPacket packet)
    {
        if (data.Length - offset < 40) return;
        var r = new ByteReader(data, offset);

        uint versionClassFlow = r.ReadUInt32();
        ushort payloadLength = r.ReadUInt16();
        byte nextHeader = r.ReadByte();
        byte hopLimit = r.ReadByte();
        var srcIp = new IPAddress(r.ReadBytes(16));
        var dstIp = new IPAddress(r.ReadBytes(16));

        var layer = new PacketLayer { Name = "IPv6", Offset = offset, Length = 40 }
            .With("Version", "6", offset, 1)
            .With("Payload Length", payloadLength.ToString(), offset + 4, 2)
            .With("Next Header", $"{nextHeader} ({IpProtocolName(nextHeader)})", offset + 6, 1)
            .With("Hop Limit", hopLimit.ToString(), offset + 7, 1)
            .With("Source", srcIp.ToString(), offset + 8, 16)
            .With("Destination", dstIp.ToString(), offset + 24, 16);
        packet.Layers.Add(layer);

        packet.Source = srcIp.ToString();
        packet.Destination = dstIp.ToString();
        packet.SourceAddress = srcIp;
        packet.DestinationAddress = dstIp;
        packet.Protocol = IpProtocolName(nextHeader);

        DispatchTransport(nextHeader, data, offset + 40, packet);
    }

    private static void DispatchTransport(byte protocol, byte[] data, int offset, ParsedPacket packet)
    {
        switch (protocol)
        {
            case 6: ParseTcp(data, offset, packet); break;
            case 17: ParseUdp(data, offset, packet); break;
            case 1: ParseIcmp(data, offset, packet, "ICMP"); break;
            case 58: ParseIcmp(data, offset, packet, "ICMPv6"); break;
            default:
                packet.Info = $"{data.Length - offset} bytes payload";
                break;
        }
    }

    private static void ParseIcmp(byte[] data, int offset, ParsedPacket packet, string name)
    {
        if (data.Length - offset < 4) return;
        byte type = data[offset];
        byte code = data[offset + 1];

        packet.Layers.Add(new PacketLayer { Name = name, Offset = offset, Length = 4 }
            .With("Type", type.ToString(), offset, 1)
            .With("Code", code.ToString(), offset + 1, 1));

        packet.Protocol = name;
        packet.Info = $"Type={type} Code={code}";
    }

    private static void ParseTcp(byte[] data, int offset, ParsedPacket packet)
    {
        if (data.Length - offset < 20) return;
        var r = new ByteReader(data, offset);

        ushort srcPort = r.ReadUInt16();
        ushort dstPort = r.ReadUInt16();
        uint seq = r.ReadUInt32();
        uint ack = r.ReadUInt32();
        byte dataOffsetByte = r.ReadByte();
        int headerLength = (dataOffsetByte >> 4) * 4;
        byte flags = r.ReadByte();
        ushort window = r.ReadUInt16();
        ushort checksum = r.ReadUInt16();
        ushort urgentPointer = r.ReadUInt16();

        var layer = new PacketLayer { Name = "TCP", Offset = offset, Length = headerLength }
            .With("Source Port", srcPort.ToString(), offset, 2)
            .With("Destination Port", dstPort.ToString(), offset + 2, 2)
            .With("Sequence Number", seq.ToString(), offset + 4, 4)
            .With("Acknowledgment Number", ack.ToString(), offset + 8, 4)
            .With("Header Length", $"{headerLength} bytes", offset + 12, 1)
            .With("Flags", DescribeTcpFlags(flags), offset + 13, 1)
            .With("Window Size", window.ToString(), offset + 14, 2)
            .With("Checksum", $"0x{checksum:X4}", offset + 16, 2)
            .With("Urgent Pointer", urgentPointer.ToString(), offset + 18, 2);
        packet.Layers.Add(layer);

        string srcIp = packet.Source;
        string dstIp = packet.Destination;
        packet.Source += $":{srcPort}";
        packet.Destination += $":{dstPort}";
        packet.SourcePort = srcPort;
        packet.DestinationPort = dstPort;
        packet.Protocol = "TCP";
        packet.Info = $"{srcPort} → {dstPort} [{DescribeTcpFlags(flags)}] Seq={seq} Ack={ack} Win={window}";

        int payloadOffset = offset + headerLength;
        int payloadLength = Math.Max(0, data.Length - payloadOffset);
        packet.Tcp = new TcpInfo(srcIp, srcPort, dstIp, dstPort, seq, flags, payloadOffset, payloadLength);

        if (payloadLength > 0)
            IdentifyApplicationLayer(data, payloadOffset, payloadLength, srcPort, dstPort, packet);
    }

    private static void ParseUdp(byte[] data, int offset, ParsedPacket packet)
    {
        if (data.Length - offset < 8) return;
        var r = new ByteReader(data, offset);

        ushort srcPort = r.ReadUInt16();
        ushort dstPort = r.ReadUInt16();
        ushort length = r.ReadUInt16();
        ushort checksum = r.ReadUInt16();

        packet.Layers.Add(new PacketLayer { Name = "UDP", Offset = offset, Length = 8 }
            .With("Source Port", srcPort.ToString(), offset, 2)
            .With("Destination Port", dstPort.ToString(), offset + 2, 2)
            .With("Length", length.ToString(), offset + 4, 2)
            .With("Checksum", $"0x{checksum:X4}", offset + 6, 2));

        packet.Source += $":{srcPort}";
        packet.Destination += $":{dstPort}";
        packet.SourcePort = srcPort;
        packet.DestinationPort = dstPort;
        packet.Protocol = "UDP";
        packet.Info = $"{srcPort} → {dstPort} Len={length}";

        int payloadOffset = offset + 8;
        int payloadLength = data.Length - payloadOffset;
        if (payloadLength > 0)
            IdentifyApplicationLayer(data, payloadOffset, payloadLength, srcPort, dstPort, packet);
    }

    private static void IdentifyApplicationLayer(
        byte[] data, int offset, int length, ushort srcPort, ushort dstPort, ParsedPacket packet)
    {
        if ((srcPort == 53 || dstPort == 53) && DnsParser.TryParse(data, offset, length, packet))
            return;

        // QUIC before TLS: it lives on UDP 443, and its Initial packets carry a ClientHello
        // that the TLS record parser would never recognise (no record layer around it).
        if ((srcPort == 443 || dstPort == 443) && packet.Protocol == "UDP"
            && QuicParser.TryParse(data, offset, length, packet))
            return;

        if (TlsRecordParser.TryParse(data, offset, length, packet))
            return;

        if ((srcPort == 80 || dstPort == 80) && HttpParser.TryParse(data, offset, length, packet))
            return;

        packet.Layers.Add(new PacketLayer { Name = "Data", Offset = offset, Length = length }
            .With("Payload", $"{length} bytes", offset, length));
    }

    private static ushort BinaryPeek16(byte[] data, int offset) =>
        (ushort)((data[offset] << 8) | data[offset + 1]);

    private static string FormatMac(PhysicalAddress mac) =>
        string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));

    private static string DescribeIPv4Flags(ushort flagsAndFragment)
    {
        bool dontFragment = (flagsAndFragment & 0x4000) != 0;
        bool moreFragments = (flagsAndFragment & 0x2000) != 0;
        int fragmentOffset = flagsAndFragment & 0x1FFF;
        var parts = new List<string>();
        if (dontFragment) parts.Add("DF");
        if (moreFragments) parts.Add("MF");
        if (fragmentOffset != 0) parts.Add($"offset={fragmentOffset}");
        return parts.Count == 0 ? "none" : string.Join(", ", parts);
    }

    private static string DescribeTcpFlags(byte flags)
    {
        var parts = new List<string>();
        if ((flags & 0x02) != 0) parts.Add("SYN");
        if ((flags & 0x10) != 0) parts.Add("ACK");
        if ((flags & 0x01) != 0) parts.Add("FIN");
        if ((flags & 0x04) != 0) parts.Add("RST");
        if ((flags & 0x08) != 0) parts.Add("PSH");
        if ((flags & 0x20) != 0) parts.Add("URG");
        return parts.Count == 0 ? "none" : string.Join(", ", parts);
    }

    private static string EtherTypeName(ushort etherType) => etherType switch
    {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x0806 => "ARP",
        0x8100 => "VLAN",
        _ => "Unknown",
    };

    private static string IpProtocolName(byte protocol) => protocol switch
    {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => $"Proto-{protocol}",
    };
}
