using Loupe.App.Localization;

namespace Loupe.App.ViewModels;

/// <summary>
/// A ready-made capture filter. BPF is precise and nobody remembers it - "udp port 443" is
/// obvious once you have seen it and impossible to guess before. The expression stays visible
/// in the filter box after picking one, so the picker doubles as a way to learn the syntax.
/// </summary>
public sealed record CaptureFilterPreset(string LabelKey, string Expression)
{
    public string Label => Loc.Get(LabelKey);

    public bool Equals(CaptureFilterPreset? other) => other is not null && Expression == other.Expression;

    public override int GetHashCode() => Expression.GetHashCode();

    public override string ToString() => Label;
}
