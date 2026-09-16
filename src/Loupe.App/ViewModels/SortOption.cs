using Loupe.App.Localization;

namespace Loupe.App.ViewModels;

/// <summary>
/// One entry in a "sort by" picker. The label is a resource key rather than text so the list
/// follows a language change like everything else.
/// </summary>
public sealed record SortOption(string Key, string LabelKey)
{
    public string Label => Loc.Get(LabelKey);

    // The picker binds to instances rebuilt on each view model, so identity is the key.
    public bool Equals(SortOption? other) => other is not null && Key == other.Key;

    public override int GetHashCode() => Key.GetHashCode();

    public override string ToString() => Label;
}
