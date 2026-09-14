using System.Windows;

namespace NetSniffer.App.Localization;

/// <summary>Looks up a localized string from the currently merged language dictionary, for use in C# (view models, etc.) rather than XAML DynamicResource bindings.</summary>
public static class Loc
{
    public static string Get(string key) =>
        Application.Current?.TryFindResource(key) as string ?? key;

    public static string Format(string key, params object?[] args) =>
        string.Format(Get(key), args);
}
