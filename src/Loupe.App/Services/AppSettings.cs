using System.IO;
using System.Text.Json;
using Loupe.Core;

namespace Loupe.App.Services;

/// <summary>
/// The handful of choices worth remembering between runs, in one small JSON file.
///
/// Written whole on every change, which is exactly why everything that persists has to live
/// here: the language used to own this file outright and would have silently dropped anything
/// else stored next to it. Bigger state (hide rules, sessions) keeps its own file.
/// </summary>
public sealed class AppSettings
{
    private static readonly string FilePath = AppStorage.PathTo("settings.json");

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static AppSettings Current { get; private set; } = Load();

    // ---- what gets remembered

    public string? Language { get; set; }

    /// <summary>Fetching site icons is the one thing that makes connections of its own.</summary>
    public bool FetchFavicons { get; set; } = true;

    /// <summary>
    /// Rows the packet grid keeps. Really a memory setting - every row pins its frame's bytes,
    /// so 50 000 rows is around 50 MB.
    /// </summary>
    public int MaxPackets { get; set; } = 50_000;

    public bool AutoScroll { get; set; } = true;
    public bool CollapseRepeats { get; set; } = true;

    /// <summary>Start capturing on the last adapter as soon as the app opens.</summary>
    public bool StartCaptureOnLaunch { get; set; }

    public string? LastAdapter { get; set; }

    public int ProxyPort { get; set; } = 8080;
    public int TransparentPort { get; set; } = 8443;
    public bool TransparentProxy { get; set; }

    // Window placement. NaN means "never saved", so the first run still centres itself.
    public double WindowWidth { get; set; } = double.NaN;
    public double WindowHeight { get; set; } = double.NaN;
    public double WindowLeft { get; set; } = double.NaN;
    public double WindowTop { get; set; } = double.NaN;
    public bool WindowMaximized { get; set; }

    // ---- storage

    private static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            // A corrupt file starts from defaults rather than taking the app down with it.
        }

        return new AppSettings();
    }

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(Current, Json));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Worst case the choice doesn't survive to the next run; nothing to interrupt for.
        }
    }

    /// <summary>Applies <paramref name="change"/> and writes the file. The one way to change a setting.</summary>
    public static void Update(Action<AppSettings> change)
    {
        change(Current);
        Save();
    }

    /// <summary>Used by the tests, which must not touch the real file.</summary>
    internal static void UseForTesting(AppSettings settings) => Current = settings;
}
