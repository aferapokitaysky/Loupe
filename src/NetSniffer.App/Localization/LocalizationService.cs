using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;

namespace NetSniffer.App.Localization;

/// <summary>
/// Runtime UI language switching via merged resource dictionaries: every
/// user-facing string in XAML is a DynamicResource, so swapping the merged
/// "Strings" dictionary re-renders the whole UI in the new language with no
/// restart needed. The chosen language is remembered between runs.
/// </summary>
public static class LocalizationService
{
    public static readonly IReadOnlyList<LanguageInfo> AvailableLanguages =
    [
        new("en", "English", "🇬🇧"),
        new("ru", "Русский", "🇷🇺"),
        new("uk", "Українська", "🇺🇦"),
        new("es", "Español", "🇪🇸"),
        new("de", "Deutsch", "🇩🇪"),
        new("fr", "Français", "🇫🇷"),
        new("pt", "Português", "🇵🇹"),
        new("it", "Italiano", "🇮🇹"),
        new("zh", "中文", "🇨🇳"),
        new("ja", "日本語", "🇯🇵"),
        new("tr", "Türkçe", "🇹🇷"),
        new("pl", "Polski", "🇵🇱"),
    ];

    private const string DefaultLanguageCode = "en";
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSniffer", "settings.json");

    public static LanguageInfo CurrentLanguage { get; private set; } = AvailableLanguages[0];

    public static event EventHandler? LanguageChanged;

    /// <summary>Call once at startup, before any window is created, so every DynamicResource resolves on first render.</summary>
    public static void Initialize()
    {
        string code = LoadSavedLanguageCode() ?? DetectSystemLanguageCode();
        SetLanguage(code, persist: false);
    }

    public static void SetLanguage(string code, bool persist = true)
    {
        var language = AvailableLanguages.FirstOrDefault(l => l.Code == code) ?? AvailableLanguages[0];

        // Relative (not "pack://application:,,,/<AssemblyName>;component/...") so this
        // doesn't break if the project's <AssemblyName> ever diverges from the project
        // name again (it already does: NetSniffer.App.csproj builds NetSniffer.dll).
        var dictionary = new ResourceDictionary
        {
            Source = new Uri($"/Localization/Strings/{language.Code}.xaml", UriKind.Relative),
        };

        var app = Application.Current;
        var existing = app.Resources.MergedDictionaries
            .FirstOrDefault(d => d.Source?.OriginalString.Contains("/Localization/Strings/") == true);
        if (existing is not null)
            app.Resources.MergedDictionaries.Remove(existing);
        app.Resources.MergedDictionaries.Add(dictionary);

        CurrentLanguage = language;
        Thread.CurrentThread.CurrentUICulture = CultureInfo.GetCultureInfo(MapToCultureName(language.Code));

        if (persist) SaveLanguageCode(language.Code);
        LanguageChanged?.Invoke(null, EventArgs.Empty);
    }

    private static string DetectSystemLanguageCode()
    {
        string systemCode = CultureInfo.InstalledUICulture.TwoLetterISOLanguageName;
        return AvailableLanguages.Any(l => l.Code == systemCode) ? systemCode : DefaultLanguageCode;
    }

    private static string MapToCultureName(string code) => code switch
    {
        "zh" => "zh-Hans",
        _ => code,
    };

    private static string? LoadSavedLanguageCode()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return null;
            using var stream = File.OpenRead(SettingsPath);
            var settings = JsonSerializer.Deserialize<AppSettings>(stream);
            return settings?.Language;
        }
        catch
        {
            return null;
        }
    }

    private static void SaveLanguageCode(string code)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new AppSettings(code)));
        }
        catch
        {
            // Non-critical: worst case the language choice doesn't persist to the next run.
        }
    }

    private sealed record AppSettings(string Language);
}
