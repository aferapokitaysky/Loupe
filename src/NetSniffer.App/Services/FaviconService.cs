using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace NetSniffer.App.Services;

/// <summary>
/// Fetches a site's favicon so hosts can be recognised at a glance instead of read letter by letter.
///
/// The icon is always fetched from the site itself - never through a third-party favicon
/// service. Those work by receiving the domain you are interested in, which would hand a
/// complete list of everything the capture saw to somebody else.
///
/// Fetching is opt-in (<see cref="Enabled"/>): it is the one part of this app that makes
/// connections of its own rather than only watching, and there are captures where that is
/// not acceptable.
/// </summary>
public sealed class FaviconService : IDisposable
{
    private const int MaxIconBytes = 512 * 1024;

    private static readonly Regex IconLinkPattern = new(
        """<link\s[^>]*rel\s*=\s*["']?[^"'>]*\bicon\b[^"'>]*["']?[^>]*>""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HrefPattern = new(
        """href\s*=\s*["']([^"']+)["']""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly HttpClient _http;
    private readonly string _cacheDirectory;
    private readonly ConcurrentDictionary<string, Task<ImageSource?>> _inFlight = new(StringComparer.OrdinalIgnoreCase);

    public FaviconService(string? cacheDirectory = null)
    {
        _cacheDirectory = cacheDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSniffer", "favicons");

        _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 3 })
        {
            Timeout = TimeSpan.FromSeconds(6),
        };
        // Some sites serve a 403 to a blank user agent.
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NetSniffer/1.0 (+favicon)");
    }

    /// <summary>When false, <see cref="GetAsync"/> only ever returns icons already on disk.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Returns the site's icon, from memory, then disk, then the network. Never throws: a host
    /// with no icon, an unreachable host and a corrupt image all come back as null.
    /// </summary>
    public Task<ImageSource?> GetAsync(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || !IsFetchableHost(host))
            return Task.FromResult<ImageSource?>(null);

        // One icon per site, not per hostname: CDN and API subdomains
        // ("c-waw06-c83c7b4d.discord.media", "s-part-0016.t-0009.t-msedge.net") never serve a
        // favicon of their own, and asking each of them would be dozens of pointless requests.
        return _inFlight.GetOrAdd(RegistrableDomain(host), LoadAsync);
    }

    /// <summary>
    /// A close-enough eTLD+1: the last two labels, or three under a common two-part public
    /// suffix (co.uk, com.au, ...). Not the full Public Suffix List - a wrong guess only costs a
    /// missing icon, which isn't worth shipping and updating a 200 KB list for.
    /// </summary>
    internal static string RegistrableDomain(string host)
    {
        string[] labels = host.TrimEnd('.').ToLowerInvariant().Split('.');
        if (labels.Length <= 2) return string.Join('.', labels);

        string lastTwo = labels[^2] + "." + labels[^1];
        bool twoPartSuffix = TwoPartSuffixes.Contains(lastTwo)
                             || (labels[^1].Length == 2 && labels[^2] is "co" or "com" or "net" or "org" or "gov" or "edu" or "ac");

        return twoPartSuffix
            ? labels[^3] + "." + lastTwo
            : lastTwo;
    }

    private static readonly HashSet<string> TwoPartSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.io", "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "blogspot.com",
    };

    private async Task<ImageSource?> LoadAsync(string host)
    {
        try
        {
            string cachePath = Path.Combine(_cacheDirectory, CacheFileName(host));
            if (File.Exists(cachePath))
            {
                // A zero-byte file is the "this host has no icon" marker, so we don't re-ask
                // on every capture.
                var cached = new FileInfo(cachePath);
                if (cached.Length == 0) return null;
                if (Decode(await File.ReadAllBytesAsync(cachePath)) is { } fromDisk) return fromDisk;
            }

            if (!Enabled) return null;

            byte[]? icon = await FetchAsync(host);
            Directory.CreateDirectory(_cacheDirectory);
            await File.WriteAllBytesAsync(cachePath, icon ?? []);
            return icon is null ? null : Decode(icon);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException
                                      or UnauthorizedAccessException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Asks the page which icon it wants first (that is where a modern site's real icon lives),
    /// then falls back to the conventional /favicon.ico.
    /// </summary>
    private async Task<byte[]?> FetchAsync(string host)
    {
        var root = new Uri($"https://{host}/");

        if (await TryGetStringAsync(root) is { } html
            && IconLinkPattern.Match(html) is { Success: true } link
            && HrefPattern.Match(link.Value) is { Success: true } href
            && Uri.TryCreate(root, href.Groups[1].Value.Trim(), out var declared)
            && declared.Scheme is "https" or "http"
            && await TryGetBytesAsync(declared) is { } declaredIcon)
        {
            return declaredIcon;
        }

        return await TryGetBytesAsync(new Uri(root, "/favicon.ico"));
    }

    private async Task<string?> TryGetStringAsync(Uri uri)
    {
        using var response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode) return null;
        if (response.Content.Headers.ContentType?.MediaType is not (null or "text/html")) return null;

        // Only the head matters, and some pages are enormous.
        var buffer = new byte[64 * 1024];
        await using var stream = await response.Content.ReadAsStreamAsync();
        int read = await stream.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false);
        return System.Text.Encoding.UTF8.GetString(buffer, 0, read);
    }

    private async Task<byte[]?> TryGetBytesAsync(Uri uri)
    {
        using var response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode) return null;
        if (response.Content.Headers.ContentLength > MaxIconBytes) return null;

        await using var stream = await response.Content.ReadAsStreamAsync();
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer);
        return buffer.Length is > 0 and <= MaxIconBytes ? buffer.ToArray() : null;
    }

    /// <summary>Decodes to a frozen bitmap so it can cross to the UI thread and be shared by rows.</summary>
    private static ImageSource? Decode(byte[] bytes)
    {
        try
        {
            using var stream = new MemoryStream(bytes);
            var image = new BitmapImage();
            image.BeginInit();
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.DecodePixelWidth = 32; // displayed at 16px; 32 keeps it crisp on a 200% display
            image.StreamSource = stream;
            image.EndInit();
            image.Freeze();
            return image;
        }
        catch (Exception e) when (e is NotSupportedException or ArgumentException or FileFormatException
                                      or OverflowException or IOException)
        {
            // Plenty of sites serve an HTML error page, or an .ico WPF won't decode.
            return null;
        }
    }

    /// <summary>A bare IP, a .local name or anything with no dot has no favicon worth asking for.</summary>
    private static bool IsFetchableHost(string host) =>
        host.Contains('.')
        && !System.Net.IPAddress.TryParse(host, out _)
        && !host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
        && Uri.CheckHostName(host) == UriHostNameType.Dns;

    private static string CacheFileName(string host)
    {
        Span<char> safe = stackalloc char[host.Length];
        for (int i = 0; i < host.Length; i++)
            safe[i] = char.IsLetterOrDigit(host[i]) || host[i] is '.' or '-' ? char.ToLowerInvariant(host[i]) : '_';

        return new string(safe) + ".icon";
    }

    public void Dispose() => _http.Dispose();
}
