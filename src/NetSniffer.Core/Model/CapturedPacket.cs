namespace NetSniffer.Core.Model;

/// <summary>Raw bytes handed up from the capture engine, before any dissection.</summary>
public sealed record CapturedPacket(
    long Number,
    DateTimeOffset Timestamp,
    byte[] Data,
    int OriginalLength);
