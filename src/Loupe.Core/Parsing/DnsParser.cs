using System.Net;
using System.Text;
using Loupe.Core.Model;

namespace Loupe.Core.Parsing;

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

        if (isResponse && answerCount > 0)
            ReadAnswers(data, offset, length, questionCount, answerCount, layer, packet);

        packet.Layers.Add(layer);
        packet.Protocol = "DNS";
        packet.Info = queryName is null
            ? (isResponse ? "Response" : "Query")
            : isResponse ? $"Response: {queryName} ({answerCount} answers)" : $"Query: {queryName} {queryType}";
        return true;
    }

    /// <summary>
    /// Walks the answer section, listing each record on the layer and - for A/AAAA - recording
    /// the address-to-name mapping. This is where the packet list gets its domain names from:
    /// every later packet to that address can be labelled with the name resolved here.
    /// </summary>
    private static void ReadAnswers(
        byte[] data, int messageStart, int messageLength,
        ushort questionCount, ushort answerCount, PacketLayer layer, ParsedPacket packet)
    {
        int messageEnd = Math.Min(data.Length, messageStart + messageLength);
        int pos = messageStart + 12;

        // Questions first: name, then the fixed 4 bytes of qtype/qclass.
        for (int i = 0; i < questionCount; i++)
        {
            if (!TryReadName(data, messageStart, pos, out _, out int afterName)) return;
            pos = afterName + 4;
            if (pos > messageEnd) return;
        }

        // Answers are capped: a malformed count shouldn't send us walking off the record.
        int limit = Math.Min((int)answerCount, 64);
        for (int i = 0; i < limit; i++)
        {
            if (!TryReadName(data, messageStart, pos, out string owner, out int afterName)) return;
            pos = afterName;
            if (pos + 10 > messageEnd) return;

            ushort type = Peek16(data, pos);
            ushort rdLength = Peek16(data, pos + 8);
            int rdStart = pos + 10;
            if (rdStart + rdLength > messageEnd) return;

            switch (type)
            {
                case 1 when rdLength == 4:
                case 28 when rdLength == 16:
                {
                    var address = new IPAddress(data.AsSpan(rdStart, rdLength));
                    layer.With(type == 1 ? "A" : "AAAA", $"{owner} → {address}", rdStart, rdLength);
                    packet.AddNameHint(address, owner, NameHintSource.DnsAnswer);
                    break;
                }

                case 5: // CNAME: no address of its own, but the alias is worth showing
                    if (TryReadName(data, messageStart, rdStart, out string alias, out _))
                        layer.With("CNAME", $"{owner} → {alias}", rdStart, rdLength);
                    break;
            }

            pos = rdStart + rdLength;
        }
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
