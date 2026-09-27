using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Loupe.Proxy;

/// <summary>
/// Toggles the current Windows user's system-wide HTTP/HTTPS proxy setting -
/// the same per-user registry values the Settings app's "Manual proxy setup"
/// writes. This is what routes browsers/apps through Loupe's proxy
/// without configuring each one individually. Entirely opt-in and reversible
/// from the same place; nothing here runs unless the user clicks the button
/// that calls it.
/// </summary>
public static class WindowsProxySettings
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;

    /// <summary>
    /// The user's proxy configuration before Loupe touched it.  A debugging tool must restore
    /// this exact state, not merely turn proxying off: the user may rely on a corporate proxy
    /// or a PAC-like local override before opening Loupe.
    /// </summary>
    public sealed record Snapshot(bool Enabled, string? ProxyServer, string? ProxyOverride);

    public static Snapshot Capture()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
        return new Snapshot(
            (key?.GetValue("ProxyEnable") as int?) == 1,
            key?.GetValue("ProxyServer") as string,
            key?.GetValue("ProxyOverride") as string);
    }

    public static bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
        return (key?.GetValue("ProxyEnable") as int?) == 1;
    }

    public static string? CurrentProxyServer()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
        return key?.GetValue("ProxyServer") as string;
    }

    public static void Enable(string host, int port)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Could not open Internet Settings registry key.");

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", $"{host}:{port}", RegistryValueKind.String);
        // Loopback/local addresses still need to bypass, or the proxy can't reach itself for local dev servers.
        key.SetValue("ProxyOverride", "localhost;127.0.0.1;<local>", RegistryValueKind.String);

        NotifySystem();
    }

    public static void Disable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Could not open Internet Settings registry key.");

        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        NotifySystem();
    }

    /// <summary>Restores the precise state observed by <see cref="Capture"/>.</summary>
    public static void Restore(Snapshot snapshot)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Could not open Internet Settings registry key.");

        key.SetValue("ProxyEnable", snapshot.Enabled ? 1 : 0, RegistryValueKind.DWord);
        SetOrDelete(key, "ProxyServer", snapshot.ProxyServer);
        SetOrDelete(key, "ProxyOverride", snapshot.ProxyOverride);
        NotifySystem();
    }

    private static void SetOrDelete(RegistryKey key, string name, string? value)
    {
        if (value is null) key.DeleteValue(name, throwOnMissingValue: false);
        else key.SetValue(name, value, RegistryValueKind.String);
    }

    private static void NotifySystem()
    {
        InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }
}
