using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using Loupe.Core;

namespace Loupe.App.Localization;

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
        new("en", "English", "Flag_GB"),
        new("ru", "Русский", "Flag_RU"),
        new("uk", "Українська", "Flag_UA"),
        new("es", "Español", "Flag_ES"),
        new("de", "Deutsch", "Flag_DE"),
        new("fr", "Français", "Flag_FR"),
        new("pt", "Português", "Flag_PT"),
        new("it", "Italiano", "Flag_IT"),
        new("zh", "中文", "Flag_CN"),
        new("ja", "日本語", "Flag_JP"),
        new("tr", "Türkçe", "Flag_TR"),
        new("pl", "Polski", "Flag_PL"),
    ];

    private const string DefaultLanguageCode = "en";

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
        // name again (it already does: Loupe.App.csproj builds Loupe.dll).
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

        // Both cultures, not just the UI one: numbers and dates are read in the same language as
        // the labels around them, so an English UI should not be reporting "2,0 KB".
        var culture = CultureInfo.GetCultureInfo(MapToCultureName(language.Code));
        Thread.CurrentThread.CurrentUICulture = culture;
        Thread.CurrentThread.CurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.DefaultThreadCurrentCulture = culture;

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

    private static string? LoadSavedLanguageCode() => Services.AppSettings.Current.Language;

    private static void SaveLanguageCode(string code) =>
        Services.AppSettings.Update(settings => settings.Language = code);

}
