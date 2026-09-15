namespace NetSniffer.App.Localization;

/// <summary>
/// One selectable UI language: its code, its own native display name, and the
/// resource key of the flag to draw for it. The flag is a vector brush from
/// Styles/Flags.xaml rather than a flag emoji - Windows' emoji font renders
/// regional-indicator sequences as bare letters ("GB", "RU"), not flags.
/// </summary>
public sealed record LanguageInfo(string Code, string NativeName, string FlagKey);
