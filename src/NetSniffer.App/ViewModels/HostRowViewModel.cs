using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using NetSniffer.App.Services;
using NetSniffer.Core.Naming;

namespace NetSniffer.App.ViewModels;

/// <summary>
/// One remote host in the hosts list: who it is, how much traffic went its way, and its
/// favicon. This is the view that stays readable when the packet grid is scrolling past
/// faster than anyone can read.
/// </summary>
public sealed partial class HostRowViewModel : ObservableObject
{
    private readonly FaviconService _favicons;
    private bool _faviconRequested;

    public HostRowViewModel(HostTraffic host, FaviconService favicons)
    {
        _favicons = favicons;
        Address = host.Address.ToString();
        Update(host);
    }

    public string Address { get; }

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private bool _hasName;
    [ObservableProperty] private long _packets;
    [ObservableProperty] private long _bytes;
    [ObservableProperty] private string _bytesText = "";
    [ObservableProperty] private string _protocols = "";
    [ObservableProperty] private string _ports = "";
    [ObservableProperty] private ImageSource? _favicon;

    /// <summary>Shown under the name; for a named host this is where the address stays visible.</summary>
    public string Subtitle => HasName ? Address : "";

    /// <summary>First letter of the name, drawn in a chip when there is no favicon to show.</summary>
    public string Initial => Name.Length > 0 ? Name[..1].ToUpperInvariant() : "?";

    public void Update(HostTraffic host)
    {
        lock (host)
        {
            bool nameChanged = Name != host.Name;
            Name = host.Name;
            HasName = host.HasName;
            Packets = host.Packets;
            Bytes = host.Bytes;
            BytesText = FormatBytes(host.Bytes);
            Protocols = string.Join(" · ", host.Protocols.OrderBy(p => p));
            Ports = string.Join(", ", host.Ports.OrderBy(p => p).Take(6));

            if (nameChanged)
            {
                OnPropertyChanged(nameof(Subtitle));
                OnPropertyChanged(nameof(Initial));
            }
        }

        RequestFavicon();
    }

    /// <summary>Asks for the icon once, and only after the host has a real domain name.</summary>
    private async void RequestFavicon()
    {
        if (_faviconRequested || !HasName || string.IsNullOrEmpty(Name)) return;
        _faviconRequested = true;

        Favicon = await _favicons.GetAsync(Name);
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB",
    };
}
