using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Loupe.App.Converters;

/// <summary>Visible when the bound value is null (pass ConverterParameter="Invert" to flip it).</summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool isNull = value is null;
        bool invert = string.Equals(parameter as string, "Invert", StringComparison.OrdinalIgnoreCase);
        return (invert ? !isNull : isNull) ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
