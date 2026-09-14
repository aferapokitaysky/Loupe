using System.Text;

namespace NetSniffer.Core.Util;

public static class HexDump
{
    /// <summary>Classic 16-bytes-per-row "offset  hex  ascii" dump, like Wireshark's byte view.</summary>
    public static string Format(ReadOnlySpan<byte> data)
    {
        const int bytesPerRow = 16;
        var sb = new StringBuilder(data.Length / bytesPerRow * 76 + 16);

        for (int rowStart = 0; rowStart < data.Length; rowStart += bytesPerRow)
        {
            int rowLength = Math.Min(bytesPerRow, data.Length - rowStart);
            sb.Append(rowStart.ToString("X4")).Append("  ");

            for (int i = 0; i < bytesPerRow; i++)
            {
                if (i < rowLength)
                    sb.Append(data[rowStart + i].ToString("X2")).Append(' ');
                else
                    sb.Append("   ");

                if (i == 7) sb.Append(' ');
            }

            sb.Append(" ");
            for (int i = 0; i < rowLength; i++)
            {
                byte b = data[rowStart + i];
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            }

            sb.Append('\n');
        }

        return sb.ToString();
    }
}
