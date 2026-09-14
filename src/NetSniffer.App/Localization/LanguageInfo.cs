namespace NetSniffer.App.Localization;

/// <summary>One selectable UI language: BCP-47-ish code, its own native display name, and a flag emoji for the picker.</summary>
public sealed record LanguageInfo(string Code, string NativeName, string Flag)
{
    public string DisplayName => $"{Flag}  {NativeName}";
}
