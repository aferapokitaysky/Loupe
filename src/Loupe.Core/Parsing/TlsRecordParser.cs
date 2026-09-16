using System.Text;
using Loupe.Core.Model;

namespace Loupe.Core.Parsing;

/// <summary>
/// Best-effort dissector for TLS record headers and the ClientHello/ServerHello
/// handshake messages - all sent in the clear even under TLS 1.3, so this needs
/// no key material. It extracts the metadata a passive observer legitimately
/// has: record type, TLS version, cipher suites offered/chosen, and the SNI
/// hostname from ClientHello. It does NOT decrypt application data.
/// Only fires when a full handshake message is present in one packet (the
/// common case - ClientHello/ServerHello rarely span a TCP segment boundary).
/// </summary>
public static class TlsRecordParser
{
    private const byte HandshakeRecordType = 22;
    private const byte ChangeCipherSpecType = 20;
    private const byte AlertType = 21;
    private const byte ApplicationDataType = 23;

    public static bool TryParse(byte[] data, int offset, int length, ParsedPacket packet)
    {
        if (length < 5) return false;

        byte recordType = data[offset];
        if (recordType is not (HandshakeRecordType or ChangeCipherSpecType or AlertType or ApplicationDataType))
            return false;

        byte versionMajor = data[offset + 1];
        byte versionMinor = data[offset + 2];
        if (versionMajor != 3) return false; // all TLS versions are 0x03,0x0{1..4}

        ushort recordLength = (ushort)((data[offset + 3] << 8) | data[offset + 4]);

        var layer = new PacketLayer { Name = "TLS", Offset = offset, Length = length }
            .With("Content Type", DescribeRecordType(recordType), offset, 1)
            .With("Version", DescribeVersion(versionMajor, versionMinor), offset + 1, 2)
            .With("Length", recordLength.ToString(), offset + 3, 2);

        packet.Protocol = "TLS";
        packet.Info = DescribeRecordType(recordType);

        if (recordType == HandshakeRecordType && length >= 6)
        {
            byte handshakeType = data[offset + 5];
            if (handshakeType == 1 && TryParseClientHello(data, offset + 5, layer, out var sni))
            {
                packet.Info = sni is null ? "Client Hello" : $"Client Hello (SNI={sni})";

                // The SNI names the server this connection is for - the one name available
                // even when the address was resolved before the capture started.
                if (sni is not null)
                    packet.AddNameHint(packet.DestinationAddress, sni, NameHintSource.TlsSni);
            }
            else if (handshakeType == 2 && TryParseServerHello(data, offset + 5, layer, out var cipher))
            {
                packet.Info = cipher is null ? "Server Hello" : $"Server Hello (cipher={cipher})";
            }
        }
        else if (recordType == ApplicationDataType)
        {
            packet.Info = $"Application Data ({recordLength} bytes, encrypted)";
        }

        packet.Layers.Add(layer);
        return true;
    }

    /// <summary>
    /// Parses a TLS ClientHello handshake message in place. Internal rather than private because
    /// QUIC carries the very same message inside CRYPTO frames, with no TLS record around it.
    /// </summary>
    internal static bool TryParseClientHello(byte[] data, int msgOffset, PacketLayer layer, out string? sni)
    {
        sni = null;
        // handshake header: type(1) length(3) ; body: version(2) random(32) sessionIdLen(1)...
        int pos = msgOffset + 4;
        if (pos + 34 > data.Length) return false;

        byte verMajor = data[pos], verMinor = data[pos + 1];
        layer.With("Handshake Type", "Client Hello", msgOffset, 1);
        layer.With("Client Version", DescribeVersion(verMajor, verMinor), pos, 2);
        pos += 2 + 32; // skip client random

        if (pos >= data.Length) return false;
        byte sessionIdLen = data[pos]; pos += 1 + sessionIdLen;
        if (pos + 2 > data.Length) return false;

        ushort cipherSuitesLen = Peek16(data, pos); pos += 2 + cipherSuitesLen;
        if (pos >= data.Length) return false;

        byte compressionLen = data[pos]; pos += 1 + compressionLen;
        if (pos + 2 > data.Length) return false;

        ushort extensionsLen = Peek16(data, pos); pos += 2;
        int extensionsEnd = Math.Min(pos + extensionsLen, data.Length);

        while (pos + 4 <= extensionsEnd)
        {
            ushort extType = Peek16(data, pos);
            ushort extLen = Peek16(data, pos + 2);
            int extBodyStart = pos + 4;
            if (extBodyStart + extLen > data.Length) break;

            if (extType == 0) // server_name
            {
                sni = TryReadServerName(data, extBodyStart, extLen);
                if (sni != null) layer.With("Server Name (SNI)", sni, extBodyStart, extLen);
            }

            pos = extBodyStart + extLen;
        }

        return true;
    }

    private static bool TryParseServerHello(byte[] data, int msgOffset, PacketLayer layer, out string? cipherSuite)
    {
        cipherSuite = null;
        int pos = msgOffset + 4;
        if (pos + 34 > data.Length) return false;

        byte verMajor = data[pos], verMinor = data[pos + 1];
        layer.With("Handshake Type", "Server Hello", msgOffset, 1);
        layer.With("Server Version", DescribeVersion(verMajor, verMinor), pos, 2);
        pos += 2 + 32;

        if (pos >= data.Length) return false;
        byte sessionIdLen = data[pos]; pos += 1 + sessionIdLen;
        if (pos + 2 > data.Length) return false;

        ushort suite = Peek16(data, pos);
        cipherSuite = CipherSuiteName(suite);
        layer.With("Cipher Suite", cipherSuite, pos, 2);
        return true;
    }

    private static string? TryReadServerName(byte[] data, int offset, int length)
    {
        // server_name_list: uint16 listLen; then [ type(1) uint16 nameLen; name ]*
        if (length < 5) return null;
        int pos = offset + 2; // skip listLen
        byte nameType = data[pos];
        if (nameType != 0) return null; // host_name
        ushort nameLen = Peek16(data, pos + 1);
        int nameStart = pos + 3;
        if (nameStart + nameLen > offset + length) return null;
        return Encoding.ASCII.GetString(data, nameStart, nameLen);
    }

    private static ushort Peek16(byte[] data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);

    private static string DescribeRecordType(byte type) => type switch
    {
        HandshakeRecordType => "Handshake",
        ChangeCipherSpecType => "Change Cipher Spec",
        AlertType => "Alert",
        ApplicationDataType => "Application Data",
        _ => $"Type {type}",
    };

    private static string DescribeVersion(byte major, byte minor) => (major, minor) switch
    {
        (3, 4) => "TLS 1.3",
        (3, 3) => "TLS 1.2",
        (3, 2) => "TLS 1.1",
        (3, 1) => "TLS 1.0",
        (3, 0) => "SSL 3.0",
        _ => $"0x{major:X2}{minor:X2}",
    };

    private static string CipherSuiteName(ushort suite) => suite switch
    {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xC02F => "ECDHE_RSA_AES128_GCM_SHA256",
        0xC030 => "ECDHE_RSA_AES256_GCM_SHA384",
        0xC02B => "ECDHE_ECDSA_AES128_GCM_SHA256",
        _ => $"0x{suite:X4}",
    };
}
