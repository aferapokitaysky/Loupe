using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace Loupe.App.Converters;

/// <summary>Resolves a resource-key string (a protocol tint, a flag drawing, ...) into the Brush it names.</summary>
public sealed class ResourceBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string key && Application.Current?.TryFindResource(key) is Brush brush
            ? brush
            : Brushes.Transparent;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
