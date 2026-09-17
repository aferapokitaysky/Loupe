using System.Runtime.InteropServices;
using System.Windows;

namespace Loupe.App.Services;

/// <summary>
/// Copying text without betting the process on it. The Windows clipboard is a shared,
/// single-owner resource: any other program can be holding it open at the moment we ask,
/// and then <see cref="Clipboard.SetText(string)"/> throws. Copying a URL is never worth a crash.
/// </summary>
public static class ClipboardService
{
    public static bool TrySetText(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;

        try
        {
            Clipboard.SetText(text);
            return true;
        }
        catch (Exception e) when (e is COMException or ExternalException or OutOfMemoryException)
        {
            return false;
        }
    }
}
