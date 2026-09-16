using System.Security.Cryptography;
using System.Text;
using Loupe.Core.Model;

namespace Loupe.Core.Parsing;

/// <summary>
/// Dissects QUIC (RFC 9000) and decrypts the Initial packet to recover the TLS ClientHello.
///
/// Worth the effort because most "UDP port 443" traffic is QUIC/HTTP-3, and without this it
/// shows up as thousands of anonymous UDP rows. Initial packets are encrypted with keys derived
/// from the connection ID using a salt published in RFC 9001 - it's obfuscation against
/// middleboxes, not secrecy, so anyone watching the wire can undo it. Everything after the
/// handshake stays encrypted with real session keys, and this makes no attempt at those.
/// </summary>
public static class QuicParser
{
    // RFC 9001 section 5.2, initial_salt for QUIC v1.
    private static readonly byte[] InitialSalt =
        [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
         0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];

    private const uint Version1 = 0x00000001;
    private const uint Version2 = 0x6b3343cf;

    public static bool TryParse(byte[] data, int offset, int length, ParsedPacket packet)
    {
        if (length < 1) return false;
        byte first = data[offset];

        // Long header: 0x80 set. Short header (0x40 set, 0x80 clear) carries no version and is
        // indistinguishable from arbitrary UDP without connection state, so it is only labelled.
        bool longHeader = (first & 0x80) != 0;
        bool fixedBit = (first & 0x40) != 0;
        if (!fixedBit) return false;

        if (!longHeader)
        {
            packet.Protocol = "QUIC";
            packet.Info = $"Protected payload ({length} bytes, encrypted)";
            packet.Layers.Add(new PacketLayer { Name = "QUIC", Offset = offset, Length = length }
                .With("Header Form", "Short (1-RTT)", offset, 1)
                .With("Payload", $"{length} bytes", offset, length));
            return true;
        }

        if (length < 7) return false;
        uint version = ReadUInt32(data, offset + 1);

        int pos = offset + 5;
        if (!TryReadConnectionId(data, ref pos, offset + length, out var destinationId)) return false;
        if (!TryReadConnectionId(data, ref pos, offset + length, out var sourceId)) return false;

        string packetType = DescribePacketType(version, first);
        var layer = new PacketLayer { Name = "QUIC", Offset = offset, Length = length }
            .With("Header Form", "Long", offset, 1)
            .With("Version", DescribeVersion(version), offset + 1, 4)
            .With("Packet Type", packetType, offset, 1)
            .With("Destination Connection ID", Hex(destinationId), 0, 0)
            .With("Source Connection ID", Hex(sourceId), 0, 0);

        packet.Protocol = "QUIC";
        packet.Info = packetType;

        if (version == 0) // Version Negotiation packet - version field of zero, no encryption
        {
            packet.Info = "Version Negotiation";
            packet.Layers.Add(layer);
            return true;
        }

        if (packetType == "Initial" && TryDecryptInitial(data, offset, length, pos, destinationId, version, layer, out var sni))
        {
            if (sni is not null)
            {
                packet.Info = $"Initial (SNI={sni})";
                packet.AddNameHint(packet.DestinationAddress, sni, NameHintSource.TlsSni);
            }
        }

        packet.Layers.Add(layer);
        return true;
    }

    /// <summary>
    /// Removes header protection and the AEAD from an Initial packet, then looks for a
    /// ClientHello in the CRYPTO frames. Returns false when the packet isn't a client Initial
    /// we can read (server Initials use a different secret, and a retried connection won't match).
    /// </summary>
    private static bool TryDecryptInitial(
        byte[] data, int offset, int length, int pos, byte[] destinationId, uint version,
        PacketLayer layer, out string? sni)
    {
        sni = null;
        int end = offset + length;

        if (!TryReadVarInt(data, ref pos, end, out ulong tokenLength)) return false;
        pos += (int)tokenLength;
        if (pos >= end) return false;

        if (!TryReadVarInt(data, ref pos, end, out ulong remaining)) return false;
        int packetNumberOffset = pos;
        if (packetNumberOffset + (int)remaining > end || remaining < 20) return false;

        var (key, iv, headerProtection) = DeriveClientInitialKeys(destinationId, version);

        // Header protection: the mask comes from ciphertext sampled 4 bytes past the packet
        // number field, whose length is itself hidden in the protected first byte.
        int sampleOffset = packetNumberOffset + 4;
        if (sampleOffset + 16 > end) return false;

        Span<byte> mask = stackalloc byte[16];
        AesEcbBlock(headerProtection, data.AsSpan(sampleOffset, 16), mask);

        byte firstByte = (byte)(data[offset] ^ (mask[0] & 0x0F));
        int packetNumberLength = (firstByte & 0x03) + 1;
        if (packetNumberOffset + packetNumberLength > end) return false;

        Span<byte> packetNumberBytes = stackalloc byte[4];
        ulong packetNumber = 0;
        for (int i = 0; i < packetNumberLength; i++)
        {
            packetNumberBytes[i] = (byte)(data[packetNumberOffset + i] ^ mask[1 + i]);
            packetNumber = (packetNumber << 8) | packetNumberBytes[i];
        }

        // Associated data is the header with protection removed; the payload is the rest.
        int headerLength = packetNumberOffset + packetNumberLength - offset;
        var associatedData = new byte[headerLength];
        Array.Copy(data, offset, associatedData, 0, headerLength);
        associatedData[0] = firstByte;
        for (int i = 0; i < packetNumberLength; i++)
            associatedData[headerLength - packetNumberLength + i] = packetNumberBytes[i];

        int cipherTextLength = (int)remaining - packetNumberLength;
        if (cipherTextLength <= 16) return false;
        int cipherTextStart = packetNumberOffset + packetNumberLength;
        if (cipherTextStart + cipherTextLength > end) return false;

        // Nonce: the IV with the packet number XORed into its right-hand end.
        var nonce = (byte[])iv.Clone();
        for (int i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(packetNumber >> (8 * i));

        var plaintext = new byte[cipherTextLength - 16];
        try
        {
            using var aead = new AesGcm(key, tagSizeInBytes: 16);
            aead.Decrypt(
                nonce,
                data.AsSpan(cipherTextStart, cipherTextLength - 16),
                data.AsSpan(cipherTextStart + cipherTextLength - 16, 16),
                plaintext,
                associatedData);
        }
        catch (CryptographicException)
        {
            // Server Initial, a Retry, or a version whose keys we didn't derive: not an error.
            return false;
        }

        layer.With("Packet Number", packetNumber.ToString(), 0, 0)
             .With("Decrypted Payload", $"{plaintext.Length} bytes", 0, 0);

        sni = ExtractSniFromCryptoFrames(plaintext, layer);
        return true;
    }

    /// <summary>
    /// Walks the decrypted frames, stitches the CRYPTO stream back together in offset order,
    /// and parses the ClientHello out of it.
    /// </summary>
    private static string? ExtractSniFromCryptoFrames(byte[] plaintext, PacketLayer layer)
    {
        var crypto = new SortedDictionary<ulong, byte[]>();
        int pos = 0;

        while (pos < plaintext.Length)
        {
            if (!TryReadVarInt(plaintext, ref pos, plaintext.Length, out ulong frameType)) break;

            switch (frameType)
            {
                case 0x00: // PADDING - runs to the end of the packet in practice
                    while (pos < plaintext.Length && plaintext[pos] == 0) pos++;
                    break;

                case 0x01: // PING
                    break;

                case 0x06: // CRYPTO
                {
                    if (!TryReadVarInt(plaintext, ref pos, plaintext.Length, out ulong cryptoOffset)) return null;
                    if (!TryReadVarInt(plaintext, ref pos, plaintext.Length, out ulong cryptoLength)) return null;
                    if (pos + (int)cryptoLength > plaintext.Length) return null;

                    crypto[cryptoOffset] = plaintext[pos..(pos + (int)cryptoLength)];
                    pos += (int)cryptoLength;
                    break;
                }

                default:
                    // Any other frame type in a client Initial means we can't keep walking safely.
                    pos = plaintext.Length;
                    break;
            }
        }

        if (crypto.Count == 0) return null;

        // Contiguous prefix only: a ClientHello split across datagrams can't be completed here.
        using var handshake = new MemoryStream();
        ulong expected = 0;
        foreach (var (cryptoOffset, chunk) in crypto)
        {
            if (cryptoOffset != expected) break;
            handshake.Write(chunk);
            expected += (ulong)chunk.Length;
        }

        byte[] message = handshake.ToArray();
        if (message.Length < 4 || message[0] != 0x01) return null; // 0x01 = ClientHello

        TlsRecordParser.TryParseClientHello(message, 0, layer, out string? sni);
        return sni;
    }

    /// <summary>RFC 9001 section 5.2: keys for the client's Initial packets, derived from the DCID.</summary>
    private static (byte[] Key, byte[] Iv, byte[] HeaderProtection) DeriveClientInitialKeys(
        byte[] destinationId, uint version)
    {
        // QUIC v2 renamed the labels; everything else about the derivation is identical.
        bool v2 = version == Version2;
        string keyLabel = v2 ? "quicv2 key" : "quic key";
        string ivLabel = v2 ? "quicv2 iv" : "quic iv";
        string hpLabel = v2 ? "quicv2 hp" : "quic hp";

        var initialSecret = HKDF.Extract(HashAlgorithmName.SHA256, destinationId, InitialSalt);
        var clientSecret = ExpandLabel(initialSecret, "client in", 32);

        return (ExpandLabel(clientSecret, keyLabel, 16),
                ExpandLabel(clientSecret, ivLabel, 12),
                ExpandLabel(clientSecret, hpLabel, 16));
    }

    /// <summary>TLS 1.3 HKDF-Expand-Label (RFC 8446) with an empty context.</summary>
    private static byte[] ExpandLabel(byte[] secret, string label, int length)
    {
        string full = "tls13 " + label;
        var info = new byte[2 + 1 + full.Length + 1];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)full.Length;
        Encoding.ASCII.GetBytes(full).CopyTo(info, 3);
        info[^1] = 0; // zero-length context

        return HKDF.Expand(HashAlgorithmName.SHA256, secret, length, info);
    }

    private static void AesEcbBlock(byte[] key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.EncryptEcb(input, output, PaddingMode.None);
    }

    private static bool TryReadConnectionId(byte[] data, ref int pos, int end, out byte[] id)
    {
        id = [];
        if (pos >= end) return false;

        byte length = data[pos++];
        if (length > 20 || pos + length > end) return false;

        id = data[pos..(pos + length)];
        pos += length;
        return true;
    }

    /// <summary>QUIC variable-length integer: the top two bits give the encoded width.</summary>
    private static bool TryReadVarInt(byte[] data, ref int pos, int end, out ulong value)
    {
        value = 0;
        if (pos >= end) return false;

        int width = 1 << (data[pos] >> 6);
        if (pos + width > end) return false;

        value = (ulong)(data[pos] & 0x3F);
        for (int i = 1; i < width; i++)
            value = (value << 8) | data[pos + i];

        pos += width;
        return true;
    }

    private static string DescribePacketType(uint version, byte first)
    {
        // The two type bits mean different things in v1 and v2 (RFC 9369 rotated them).
        int type = (first >> 4) & 0x03;
        if (version == Version2)
        {
            return type switch
            {
                0 => "Retry", 1 => "Initial", 2 => "0-RTT", _ => "Handshake",
            };
        }

        return type switch
        {
            0 => "Initial", 1 => "0-RTT", 2 => "Handshake", _ => "Retry",
        };
    }

    private static string DescribeVersion(uint version) => version switch
    {
        0 => "Version Negotiation",
        Version1 => "1 (RFC 9000)",
        Version2 => "2 (RFC 9369)",
        _ when (version & 0x0F0F0F0F) == 0x0a0a0a0a => $"0x{version:X8} (GREASE)",
        _ => $"0x{version:X8}",
    };

    private static uint ReadUInt32(byte[] data, int offset) =>
        (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);

    private static string Hex(byte[] bytes) =>
        bytes.Length == 0 ? "(empty)" : Convert.ToHexString(bytes).ToLowerInvariant();
}
