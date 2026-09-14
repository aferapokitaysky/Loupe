using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace NetSniffer.App.Converters;

/// <summary>Int count -&gt; Visibility. Visible when the count is zero (pass ConverterParameter="Invert" to flip that).</summary>
public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool isEmpty = value is int count && count == 0;
        bool invert = string.Equals(parameter as string, "Invert", StringComparison.OrdinalIgnoreCase);
        bool visible = invert ? !isEmpty : isEmpty;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
