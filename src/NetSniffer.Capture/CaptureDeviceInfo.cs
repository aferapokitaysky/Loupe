namespace NetSniffer.Capture;

/// <summary>One network adapter available for capture.</summary>
public sealed record CaptureDeviceInfo(string Name, string Description)
{
    public override string ToString() => Description;
}
