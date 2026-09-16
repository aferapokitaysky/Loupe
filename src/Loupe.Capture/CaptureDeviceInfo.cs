namespace Loupe.Capture;

/// <summary>What kind of interface a capture device actually is, so the UI can say so plainly.</summary>
public enum AdapterKind
{
    /// <summary>Not backed by a recognisable Windows interface - WAN miniports, pcap's loopback shim, and similar.</summary>
    Other,
    Ethernet,
    WiFi,
    Bluetooth,
    Loopback,
    Virtual,
}

/// <summary>One network adapter available for capture.</summary>
public sealed record CaptureDeviceInfo(string Name, string Description)
{
    public AdapterKind Kind { get; init; } = AdapterKind.Other;

    /// <summary>True for the adapter the OS would route internet traffic through right now.</summary>
    public bool IsInternet { get; init; }

    /// <summary>
    /// What the adapter dropdown shows: the connection type up front (a raw driver name like
    /// "Realtek 8852CE WiFi 6E PCI-E NIC" doesn't tell you which one your traffic uses), with
    /// the live internet adapter marked.
    /// </summary>
    public string Label
    {
        get
        {
            string prefix = Kind switch
            {
                AdapterKind.Ethernet => "Ethernet · ",
                AdapterKind.WiFi => "Wi-Fi · ",
                AdapterKind.Bluetooth => "Bluetooth · ",
                AdapterKind.Loopback => "Loopback · ",
                AdapterKind.Virtual => "Virtual · ",
                _ => "",
            };
            return IsInternet ? $"★ {prefix}{Description}" : $"{prefix}{Description}";
        }
    }

    public override string ToString() => Label;
}
