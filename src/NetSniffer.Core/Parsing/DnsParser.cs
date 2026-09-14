using System.Text;
using NetSniffer.Core.Model;

namespace NetSniffer.Core.Parsing;

public static class DnsParser
{
    public static bool TryParse(byte[] data, int offset, int length, ParsedPacket packet)
    {
        if (length < 12) return false;

        ushort id = Peek16(data, offset);
        byte flagsHi = data[offset + 2];
        bool isResponse = (flagsHi & 0x80) != 0;
        byte opcode = (byte)((flagsHi >> 3) & 0x0F);
        ushort questionCount = Peek16(data, offset + 4);
        ushort answerCount = Peek16(data, offset + 6);

        if (opcode != 0 || questionCount == 0 || questionCount > 32) return false; // not a plausible standard query

        int pos = offset + 12;
        string? queryName = null;
        string? queryType = null;

        if (questionCount > 0 && TryReadName(data, offset, pos, out var name, out var newPos) && newPos + 4 <= data.Length)
        {
            queryName = name;
            ushort qtype = Peek16(data, newPos);
            queryType = DnsTypeName(qtype);
        }

        var layer = new PacketLayer { Name = "DNS", Offset = offset, Length = length }
            .With("Transaction ID", $"0x{id:X4}", offset, 2)
            .With("Type", isResponse ? "Response" : "Query", offset + 2, 1)
            .With("Questions", questionCount.ToString(), offset + 4, 2)
            .With("Answer RRs", answerCount.ToString(), offset + 6, 2);

        if (queryName != null)
            layer.With("Query Name", queryName, pos, 0).With("Query Type", queryType!, 0, 0);

        packet.Layers.Add(layer);
        packet.Protocol = "DNS";
        packet.Info = queryName is null
            ? (isResponse ? "Response" : "Query")
            : isResponse ? $"Response: {queryName} ({answerCount} answers)" : $"Query: {queryName} {queryType}";
        return true;
    }

    /// <summary>Reads a (possibly compressed) DNS name starting at <paramref name="pos"/> within the full frame.</summary>
    private static bool TryReadName(byte[] data, int messageStart, int pos, out string name, out int endPos)
    {
        var labels = new List<string>();
        int cursor = pos;
        int jumps = 0;
        int? returnPos = null;

        while (cursor < data.Length)
        {
            byte lengthByte = data[cursor];
            if (lengthByte == 0)
            {
                cursor++;
                break;
            }

            if ((lengthByte & 0xC0) == 0xC0) // compression pointer
            {
                if (cursor + 1 >= data.Length || ++jumps > 16) { name = ""; endPos = pos; return false; }
                returnPos ??= cursor + 2;
                int pointer = ((lengthByte & 0x3F) << 8) | data[cursor + 1];
                cursor = messageStart + pointer; // DNS pointers are offsets from the start of the DNS message
                continue;
            }

            if (cursor + 1 + lengthByte > data.Length) { name = ""; endPos = pos; return false; }
            labels.Add(Encoding.ASCII.GetString(data, cursor + 1, lengthByte));
            cursor += 1 + lengthByte;
        }

        name = string.Join('.', labels);
        endPos = returnPos ?? cursor;
        return true;
    }

    private static ushort Peek16(byte[] data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);

    private static string DnsTypeName(ushort type) => type switch
    {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        2 => "NS",
        12 => "PTR",
        33 => "SRV",
        _ => type.ToString(),
    };
}
