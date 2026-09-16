using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Loupe.App.Services;

/// <summary>
/// The small shell icon of an executable, so a program is recognised by its icon the way it is
/// in the taskbar - faster than reading "msedgewebview2" in a column.
/// </summary>
public static class AppIconService
{
    private static readonly ConcurrentDictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Frozen icon for <paramref name="imagePath"/>, or null. Call from the UI thread: the shell
    /// API wants an STA with COM initialised, which the parser thread is not. Rows ask for it
    /// lazily from a binding, so that is where it runs, and each executable is loaded once.
    /// </summary>
    public static ImageSource? Get(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return null;
        return Cache.GetOrAdd(imagePath, Load);
    }

    private static ImageSource? Load(string path)
    {
        var info = new ShFileInfo();
        IntPtr result = SHGetFileInfoW(path, 0, ref info, (uint)Marshal.SizeOf<ShFileInfo>(), ShgfiIcon | ShgfiSmallIcon);
        if (result == IntPtr.Zero || info.hIcon == IntPtr.Zero) return null;

        try
        {
            var source = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            source.Freeze(); // shared by every row that shows this program
            return source;
        }
        catch (Exception e) when (e is COMException or ArgumentException)
        {
            return null;
        }
        finally
        {
            DestroyIcon(info.hIcon); // CreateBitmapSourceFromHIcon copies the pixels
        }
    }

    private const uint ShgfiIcon = 0x100;
    private const uint ShgfiSmallIcon = 0x1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShFileInfo
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfoW(string path, uint attributes, ref ShFileInfo info, uint size, uint flags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);
}
