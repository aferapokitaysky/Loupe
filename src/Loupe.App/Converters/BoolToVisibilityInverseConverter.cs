using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Loupe.App.Converters;

/// <summary>True -&gt; Collapsed, False -&gt; Visible. Handy for "show X while not capturing" bindings.</summary>
public sealed class BoolToVisibilityInverseConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
