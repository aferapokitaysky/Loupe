using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using Loupe.App.Services;
using Loupe.Core.Naming;

namespace Loupe.App.ViewModels;

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
        AddressValue = host.Address;
        Address = host.Address.ToString();
        Update(host);
    }

    public string Address { get; }

    /// <summary>Typed form, for filtering packets without formatting 50k addresses back to text.</summary>
    public System.Net.IPAddress AddressValue { get; }

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private bool _hasName;
    [ObservableProperty] private long _packets;
    [ObservableProperty] private long _bytes;
    [ObservableProperty] private string _bytesText = "";
    [ObservableProperty] private string _protocols = "";
    [ObservableProperty] private string _ports = "";
    [ObservableProperty] private ImageSource? _favicon;

    /// <summary>Ticked in the hosts panel to filter the packet list by this host. Several can be
    /// ticked at once - watching two or three domains against each other is the normal case.</summary>
    [ObservableProperty] private bool _isChecked;

    /// <summary>Timestamp of the last packet, for "most recent first" sorting.</summary>
    [ObservableProperty] private DateTimeOffset _lastSeen;

    /// <summary>Programs that talked to this host - "chrome", or "chrome, Telegram" for a CDN.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProcess))]
    private string _processText = "";

    [ObservableProperty] private ImageSource? _processIcon;

    public bool HasProcess => ProcessText.Length > 0;

    /// <summary>Every program seen on this host, for hide rules and search.</summary>
    public IReadOnlyList<string> ProcessNames { get; private set; } = [];

    private string? _processIconPath;

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
            LastSeen = host.LastSeen;
            BytesText = FormatBytes(host.Bytes);
            Protocols = string.Join(" · ", host.Protocols.OrderBy(p => p));
            Ports = string.Join(", ", host.Ports.OrderBy(p => p).Take(6));

            if (host.Processes.Count > 0)
            {
                if (host.Processes.Count != ProcessNames.Count)
                    ProcessNames = [.. host.Processes.Keys];

                ProcessText = string.Join(", ", host.Processes.Keys.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).Take(3))
                              + (host.Processes.Count > 3 ? $" +{host.Processes.Count - 3}" : "");

                // Update() runs on the UI thread (the drain tick), which is where the shell icon
                // API has to be called. Only reload when the first program's executable changed.
                string? path = host.Processes.Values.FirstOrDefault(p => p is not null);
                if (path != _processIconPath)
                {
                    _processIconPath = path;
                    ProcessIcon = AppIconService.Get(path);
                }
            }

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

        // async void has nowhere to send an exception but the dispatcher, where it becomes an
        // error dialog. A missing icon is not worth one.
        try
        {
            Favicon = await _favicons.GetAsync(Name);
        }
        catch (Exception)
        {
            Favicon = null;
        }
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB",
    };
}
