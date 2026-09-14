using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace NetSniffer.App.Converters;

/// <summary>Resolves a <see cref="PacketRowViewModel.ColorKey"/> resource name into the actual Brush from App.xaml.</summary>
public sealed class ProtocolColorConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string key && Application.Current.TryFindResource(key) is Brush brush)
            return brush;
        return Brushes.Transparent;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
