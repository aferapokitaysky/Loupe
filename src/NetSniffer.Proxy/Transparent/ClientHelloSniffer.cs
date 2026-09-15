namespace NetSniffer.Proxy.Transparent;

/// <summary>
/// Reads the server name out of a TLS ClientHello without consuming it.
///
/// In transparent mode nobody sends a CONNECT line, so the SNI is the only thing that says
/// which server the client wanted. The bytes are handed back untouched so they can be replayed
/// into the TLS handshake afterwards.
/// </summary>
public static class ClientHelloSniffer
{
    private const byte HandshakeRecord = 0x16;
    private const byte ClientHelloType = 0x01;

    /// <summary>True when the buffer starts like a TLS handshake record.</summary>
    public static bool LooksLikeTls(ReadOnlySpan<byte> buffer) =>
        buffer.Length >= 3 && buffer[0] == HandshakeRecord && buffer[1] == 0x03;

    /// <summary>
    /// Extracts the server_name extension. Returns false for a ClientHello without an SNI
    /// (an old client, or one connecting to a bare address), which simply can't be routed
    /// transparently - there is nothing in the connection that names the destination.
    /// </summary>
    public static bool TryGetServerName(ReadOnlySpan<byte> buffer, out string serverName)
    {
        serverName = "";
        if (!LooksLikeTls(buffer) || buffer.Length < 45) return false;

        int recordLength = (buffer[3] << 8) | buffer[4];
        int end = Math.Min(buffer.Length, 5 + recordLength);

        int pos = 5;
        if (pos >= end || buffer[pos] != ClientHelloType) return false;

        pos += 4;            // handshake type (1) + length (3)
        pos += 2 + 32;       // client version + random
        if (pos >= end) return false;

        int sessionIdLength = buffer[pos];
        pos += 1 + sessionIdLength;
        if (pos + 2 > end) return false;

        int cipherSuitesLength = (buffer[pos] << 8) | buffer[pos + 1];
        pos += 2 + cipherSuitesLength;
        if (pos >= end) return false;

        int compressionLength = buffer[pos];
        pos += 1 + compressionLength;
        if (pos + 2 > end) return false;

        int extensionsLength = (buffer[pos] << 8) | buffer[pos + 1];
        pos += 2;
        int extensionsEnd = Math.Min(pos + extensionsLength, end);

        while (pos + 4 <= extensionsEnd)
        {
            int extensionType = (buffer[pos] << 8) | buffer[pos + 1];
            int extensionLength = (buffer[pos + 2] << 8) | buffer[pos + 3];
            int body = pos + 4;
            if (body + extensionLength > extensionsEnd) return false;

            if (extensionType == 0x0000) // server_name
                return TryReadHostName(buffer[body..(body + extensionLength)], out serverName);

            pos = body + extensionLength;
        }

        return false;
    }

    /// <summary>server_name_list: uint16 list length, then entries of [type(1), uint16 length, name].</summary>
    private static bool TryReadHostName(ReadOnlySpan<byte> body, out string serverName)
    {
        serverName = "";
        if (body.Length < 5) return false;

        int pos = 2; // skip the list length
        while (pos + 3 <= body.Length)
        {
            byte nameType = body[pos];
            int nameLength = (body[pos + 1] << 8) | body[pos + 2];
            int nameStart = pos + 3;
            if (nameStart + nameLength > body.Length) return false;

            if (nameType == 0) // host_name
            {
                serverName = System.Text.Encoding.ASCII.GetString(body[nameStart..(nameStart + nameLength)]);
                return serverName.Length > 0;
            }

            pos = nameStart + nameLength;
        }

        return false;
    }
}
