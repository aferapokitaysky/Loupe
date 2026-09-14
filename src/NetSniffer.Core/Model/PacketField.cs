namespace NetSniffer.Core.Model;

/// <summary>
/// One human-readable field inside a protocol layer (e.g. "Source Port: 443"),
/// with the byte range it came from so the UI can highlight it in a hex view.
/// </summary>
public sealed record PacketField(string Name, string Value, int Offset, int Length);
