using System.IO;
using System.Text.Json;
using Loupe.Core;
using Loupe.Core.Naming;

namespace Loupe.App.Services;

/// <summary>
/// The one set of hide rules shared by the packet and proxy pages, kept across launches: a
/// program you hid yesterday is still noise today.
///
/// Its own file rather than a key in settings.json - the language setting rewrites that file
/// whole, and would silently drop the list.
/// </summary>
public static class IgnoreListStore
{
    private static readonly string FilePath = AppStorage.PathTo("ignore.json");

    public static IgnoreRules Rules { get; } = Create();

    private static IgnoreRules Create()
    {
        var rules = new IgnoreRules();

        try
        {
            if (File.Exists(FilePath))
            {
                var saved = JsonSerializer.Deserialize<Saved>(File.ReadAllText(FilePath));
                rules.Load(saved?.Processes, saved?.Hosts);
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            // A corrupt or unreadable list starts empty rather than taking the app down.
        }

        rules.Changed += (_, _) => Save(rules);
        return rules;
    }

    private static void Save(IgnoreRules rules)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(new Saved([.. rules.Processes], [.. rules.Hosts])));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Not being able to persist the list is no reason to stop hiding things this session.
        }
    }

    private sealed record Saved(List<string> Processes, List<string> Hosts);
}
