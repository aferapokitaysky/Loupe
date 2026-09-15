using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSniffer.Core.Sessions;

/// <summary>A saved capture: what it was, when it was taken, and how big it is.</summary>
public sealed record SessionInfo
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required DateTimeOffset Created { get; init; }

    /// <summary>Adapter description for a live capture, the file name for an imported one.</summary>
    public string? Source { get; init; }

    public long PacketCount { get; init; }
    public long ByteCount { get; init; }
    public int HostCount { get; init; }
    public int RequestCount { get; init; }

    /// <summary>Where the payload files live. Not serialised - it follows from the store root.</summary>
    [JsonIgnore] public string Directory { get; init; } = "";

    /// <summary>Total bytes on disk. Not serialised: it is measured when listing.</summary>
    [JsonIgnore] public long SizeOnDisk { get; init; }

    [JsonIgnore] public bool HasPackets => PacketCount > 0;
    [JsonIgnore] public bool HasRequests => RequestCount > 0;
}

/// <summary>
/// Saved sessions - a capture you can come back to instead of losing it when the window closes.
///
/// One folder per session holding the payloads (a .pcap, the proxy's requests) next to a small
/// session.json. A folder rather than one packed file so the capture stays an ordinary .pcap:
/// it opens in Wireshark, and nothing here is needed to read it back.
/// </summary>
public sealed class SessionStore
{
    public const string CaptureFileName = "capture.pcap";
    public const string RequestsFileName = "requests.json";
    private const string MetadataFileName = "session.json";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public SessionStore(string? root = null)
    {
        Root = root ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSniffer", "sessions");
    }

    public string Root { get; }

    /// <summary>Newest first. Unreadable or half-written folders are skipped, never thrown over.</summary>
    public IReadOnlyList<SessionInfo> List()
    {
        if (!Directory.Exists(Root)) return [];

        var sessions = new List<SessionInfo>();
        foreach (string folder in Directory.EnumerateDirectories(Root))
        {
            if (TryRead(folder) is { } session) sessions.Add(session);
        }

        return [.. sessions.OrderByDescending(s => s.Created)];
    }

    public SessionInfo? Get(string id) =>
        TryRead(Path.Combine(Root, id));

    /// <summary>
    /// Creates the folder for a new session and writes its metadata. The caller then drops the
    /// payload files in <see cref="SessionInfo.Directory"/> - the store keeps no opinion about
    /// what they contain, so a session can hold packets, requests, or both.
    /// </summary>
    public SessionInfo Create(string name, SessionInfo details)
    {
        string id = $"{DateTimeOffset.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6]}";
        string folder = Path.Combine(Root, id);
        Directory.CreateDirectory(folder);

        var session = details with
        {
            Id = id,
            Name = Sanitize(name),
            Created = DateTimeOffset.Now,
            Directory = folder,
        };

        Write(session);
        return session;
    }

    public SessionInfo Rename(string id, string newName)
    {
        var session = Get(id) ?? throw new DirectoryNotFoundException($"No session '{id}'.");
        var renamed = session with { Name = Sanitize(newName) };
        Write(renamed);
        return renamed;
    }

    /// <summary>Deletes the session and everything in it. Irreversible - confirm before calling.</summary>
    public void Delete(string id)
    {
        // Guard against a caller passing something like "..\..": only a plain folder name here.
        if (string.IsNullOrWhiteSpace(id) || id.Contains(Path.DirectorySeparatorChar) || id.Contains("..")) return;

        string folder = Path.Combine(Root, id);
        if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
    }

    public string PathTo(SessionInfo session, string fileName) => Path.Combine(session.Directory, fileName);

    private SessionInfo? TryRead(string folder)
    {
        try
        {
            string metadataPath = Path.Combine(folder, MetadataFileName);
            if (!File.Exists(metadataPath)) return null;

            var session = JsonSerializer.Deserialize<SessionInfo>(File.ReadAllText(metadataPath));
            if (session is null) return null;

            return session with
            {
                Directory = folder,
                SizeOnDisk = MeasureFolder(folder),
            };
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            return null; // a session being written right now, or one somebody edited by hand
        }
    }

    private void Write(SessionInfo session) =>
        File.WriteAllText(Path.Combine(session.Directory, MetadataFileName), JsonSerializer.Serialize(session, Json));

    private static long MeasureFolder(string folder)
    {
        long total = 0;
        foreach (string file in Directory.EnumerateFiles(folder))
        {
            try { total += new FileInfo(file).Length; }
            catch (IOException) { }
        }

        return total;
    }

    /// <summary>Names are shown, never used as paths - but keep them to one tidy line anyway.</summary>
    private static string Sanitize(string name)
    {
        string trimmed = new string(name.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (trimmed.Length == 0) return "Session";
        return trimmed.Length <= 80 ? trimmed : trimmed[..80];
    }
}
