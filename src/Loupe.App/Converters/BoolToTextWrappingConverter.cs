using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Loupe.App.Converters;

/// <summary>
/// True wraps, false lets long lines run off to the side.
///
/// Both are right sometimes: a request body is read, so it wraps; a hex dump is a grid of
/// columns and wrapping turns it into mush. So it is a switch, not a decision made once here.
/// </summary>
public sealed class BoolToTextWrappingConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? TextWrapping.Wrap : TextWrapping.NoWrap;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is TextWrapping.Wrap;
}
