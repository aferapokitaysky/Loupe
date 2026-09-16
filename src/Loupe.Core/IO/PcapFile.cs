using Loupe.Core.Model;

namespace Loupe.Core.IO;

/// <summary>
/// Reads/writes the classic libpcap file format (.pcap), so captures made
/// with Loupe can be opened in Wireshark/tcpdump and vice versa.
/// Does not implement pcapng - that's a reasonable follow-up, not needed for
/// basic interop.
/// </summary>
public static class PcapFile
{
    private const uint MagicLittleEndian = 0xA1B2C3D4;
    private const ushort VersionMajor = 2;
    private const ushort VersionMinor = 4;
    private const uint LinkTypeEthernet = 1;

    public static void Write(string path, IEnumerable<CapturedPacket> packets)
    {
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var writer = new BinaryWriter(stream);

        writer.Write(MagicLittleEndian);
        writer.Write(VersionMajor);
        writer.Write(VersionMinor);
        writer.Write(0); // thiszone (GMT)
        writer.Write(0U); // sigfigs
        writer.Write(262144U); // snaplen
        writer.Write(LinkTypeEthernet);

        foreach (var packet in packets)
        {
            uint seconds = (uint)(packet.Timestamp.ToUnixTimeSeconds());
            uint microseconds = (uint)(packet.Timestamp.UtcDateTime.Ticks / 10 % 1_000_000);

            writer.Write(seconds);
            writer.Write(microseconds);
            writer.Write((uint)packet.Data.Length);
            writer.Write((uint)packet.OriginalLength);
            writer.Write(packet.Data);
        }
    }

    public static IEnumerable<CapturedPacket> Read(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read);
        using var reader = new BinaryReader(stream);

        uint magic = reader.ReadUInt32();
        bool swapEndian = magic switch
        {
            MagicLittleEndian => false,
            0xD4C3B2A1 => true,
            _ => throw new InvalidDataException("Not a .pcap file (bad magic number)."),
        };

        reader.ReadUInt16(); reader.ReadUInt16(); // version major/minor
        reader.ReadInt32();                        // thiszone
        reader.ReadUInt32();                        // sigfigs
        reader.ReadUInt32();                        // snaplen
        reader.ReadUInt32();                        // linktype (assumed Ethernet)

        long number = 0;
        while (stream.Position < stream.Length)
        {
            uint seconds = ReadU32(reader, swapEndian);
            uint microseconds = ReadU32(reader, swapEndian);
            uint capturedLength = ReadU32(reader, swapEndian);
            uint originalLength = ReadU32(reader, swapEndian);

            byte[] data = reader.ReadBytes((int)capturedLength);
            if (data.Length != capturedLength) yield break; // truncated file

            var timestamp = DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(microseconds * 10);
            yield return new CapturedPacket(++number, timestamp, data, (int)originalLength);
        }
    }

    private static uint ReadU32(BinaryReader reader, bool swap)
    {
        uint value = reader.ReadUInt32();
        return swap
            ? ((value & 0x000000FF) << 24) | ((value & 0x0000FF00) << 8) |
              ((value & 0x00FF0000) >> 8) | ((value & 0xFF000000) >> 24)
            : value;
    }
}
