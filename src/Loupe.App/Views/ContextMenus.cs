using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Loupe.App.Views;

/// <summary>
/// Context menus built at the moment they open, so each item can name exactly what it acts on
/// ("Hide powershell") instead of a generic "Hide program" the user has to trust.
/// </summary>
internal static class ContextMenus
{
    public static MenuItem Item(string header, string symbol, Action onClick)
    {
        var item = new MenuItem
        {
            // A lone "_" is an access-key marker in a menu header; host and program names carry
            // real underscores ("steam_monitor"), so every one of them is doubled to stay literal.
            Header = header.Replace("_", "__"),
            Icon = new Wpf.Ui.Controls.SymbolIcon
            {
                // TryParse: an icon name missing from this WPF-UI version must cost the icon, not the menu.
                Symbol = Enum.TryParse<Wpf.Ui.Controls.SymbolRegular>(symbol, out var parsed)
                    ? parsed
                    : Wpf.Ui.Controls.SymbolRegular.Empty,
                FontSize = 14,
            },
        };
        item.Click += (_, _) => onClick();
        return item;
    }

    /// <summary>The view model of the row or item under the pointer, whichever template it is in.</summary>
    public static T? FindDataContext<T>(object? source) where T : class
    {
        for (var node = source as DependencyObject; node is not null; node = GetParent(node))
        {
            if (node is FrameworkElement { DataContext: T match }) return match;
        }

        return null;

        // Runs inside a template can be FrameworkContentElements, which VisualTreeHelper rejects.
        static DependencyObject? GetParent(DependencyObject node) =>
            node is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(node)
                : LogicalTreeHelper.GetParent(node);
    }
}
