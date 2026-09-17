using System.Globalization;
using System.Windows.Data;

namespace Loupe.App.Converters;

/// <summary>
/// A 0..1 share into a bar width, given the track width as the parameter.
///
/// A Grid with star columns would be the usual way to draw a proportion, but these bars live
/// inside a virtualized list item where the track has no measured width to share out yet - so
/// the width the bar should have is computed from the number instead.
/// </summary>
public sealed class ShareToWidthConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        double share = value switch
        {
            double d => d,
            float f => f,
            _ => 0,
        };

        double track = parameter is string text && double.TryParse(text, NumberStyles.Any, CultureInfo.InvariantCulture, out double parsed)
            ? parsed
            : 72;

        if (double.IsNaN(share) || share <= 0) return 0d;

        // A hairline for anything that carried traffic at all: a host that is present but
        // invisible reads as a rendering bug.
        return Math.Max(2, Math.Min(1, share) * track);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
